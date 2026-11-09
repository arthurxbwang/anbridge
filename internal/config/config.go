package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

type TLS struct {
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
}

type Nginx struct {
	Binary                string `json:"binary"`
	Config                string `json:"config"`
	Prefix                string `json:"prefix"`
	CommandTimeoutSeconds int    `json:"command_timeout_seconds"`
}

type Probe struct {
	Address    string `json:"address"`
	ServerName string `json:"server_name"`
}

type Site struct {
	ID          string   `json:"id"`
	TokenFile   string   `json:"token_file"`
	Domains     []string `json:"domains"`
	IncludeFile string   `json:"include_file"`
	CAFile      string   `json:"ca_file,omitempty"`
	Probes      []Probe  `json:"probes"`
}

type Config struct {
	Listen              string `json:"listen"`
	TLS                 TLS    `json:"tls"`
	APIStateDir         string `json:"api_state_dir"`
	DeployStateDir      string `json:"deploy_state_dir"`
	SocketPath          string `json:"socket_path"`
	SocketGroup         string `json:"socket_group"`
	ProbeTimeoutSeconds int    `json:"probe_timeout_seconds"`
	MinValidityHours    int    `json:"min_validity_hours"`
	MaxStagedPerSite    int    `json:"max_staged_per_site"`
	StagedTTLHours      int    `json:"staged_ttl_hours"`
	Nginx               Nginx  `json:"nginx"`
	Sites               []Site `json:"sites"`
}

var siteID = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
var dnsName = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$`)
var safePath = regexp.MustCompile(`^/[a-zA-Z0-9_./+-]+$`)

func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var c Config
	d := json.NewDecoder(io.LimitReader(f, 1024*1024))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return nil, errors.New("config must contain one JSON object")
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) Validate() error {
	if c.Listen == "" {
		c.Listen = "127.0.0.1:9443"
	}
	if _, _, err := net.SplitHostPort(c.Listen); err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	if c.ProbeTimeoutSeconds == 0 {
		c.ProbeTimeoutSeconds = 10
	}
	if c.Nginx.CommandTimeoutSeconds == 0 {
		c.Nginx.CommandTimeoutSeconds = 10
	}
	if c.MinValidityHours == 0 {
		c.MinValidityHours = 24
	}
	if c.MaxStagedPerSite == 0 {
		c.MaxStagedPerSite = 16
	}
	if c.StagedTTLHours == 0 {
		c.StagedTTLHours = 48
	}
	if c.ProbeTimeoutSeconds < 1 || c.ProbeTimeoutSeconds > 60 ||
		c.Nginx.CommandTimeoutSeconds < 1 || c.Nginx.CommandTimeoutSeconds > 60 ||
		c.MinValidityHours < 1 || c.MaxStagedPerSite < 1 || c.MaxStagedPerSite > 1000 ||
		c.StagedTTLHours < 1 || c.StagedTTLHours > 720 {
		return errors.New("timeout, validity, or staged certificate limits out of range")
	}
	paths := []string{c.APIStateDir, c.DeployStateDir, c.SocketPath,
		c.TLS.CertFile, c.TLS.KeyFile, c.Nginx.Binary, c.Nginx.Config, c.Nginx.Prefix}
	if len(c.Sites) == 0 {
		return errors.New("at least one site is required")
	}
	ids, includes, tokens := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, s := range c.Sites {
		if !siteID.MatchString(s.ID) || ids[s.ID] {
			return fmt.Errorf("invalid or duplicate site ID %q", s.ID)
		}
		ids[s.ID] = true
		if includes[s.IncludeFile] || tokens[s.TokenFile] {
			return errors.New("each site must have a distinct include file and token file")
		}
		includes[s.IncludeFile], tokens[s.TokenFile] = true, true
		paths = append(paths, s.IncludeFile, s.TokenFile)
		if s.CAFile != "" {
			paths = append(paths, s.CAFile)
		}
		if len(s.Domains) == 0 || len(s.Probes) == 0 {
			return fmt.Errorf("site %s requires domains and probes", s.ID)
		}
		domains := map[string]bool{}
		for _, name := range s.Domains {
			if !validName(name) || domains[name] {
				return fmt.Errorf("invalid or duplicate domain in site %s", s.ID)
			}
			domains[name] = true
		}
		probed := map[string]bool{}
		for _, p := range s.Probes {
			host, port, err := net.SplitHostPort(p.Address)
			ip := net.ParseIP(host)
			if err != nil || ip == nil || !ip.IsLoopback() || port == "" {
				return fmt.Errorf("site %s probes must use a literal loopback IP and port", s.ID)
			}
			if !domains[p.ServerName] {
				return fmt.Errorf("site %s probe server_name must be a configured domain", s.ID)
			}
			probed[p.ServerName] = true
		}
		for name := range domains {
			if !probed[name] {
				return fmt.Errorf("site %s has no TLS probe for domain %s", s.ID, name)
			}
		}
	}
	for _, path := range paths {
		if !safePath.MatchString(path) || filepath.Clean(path) != path || path == "/" {
			return fmt.Errorf("path %q must be an absolute clean path without whitespace or config metacharacters", path)
		}
	}
	if inside(c.APIStateDir, c.DeployStateDir) || inside(c.DeployStateDir, c.APIStateDir) {
		return errors.New("API and deploy state directories must be separate")
	}
	for _, path := range append([]string{c.SocketPath, c.Nginx.Binary, c.Nginx.Config, c.Nginx.Prefix}, includePaths(c.Sites)...) {
		if inside(c.APIStateDir, path) {
			return errors.New("privileged paths must not be inside API state")
		}
	}
	return nil
}

func validName(name string) bool {
	if len(name) > 253 || !dnsName.MatchString(name) || strings.Contains(name, "..") {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
	}
	return true
}

func inside(parent, child string) bool {
	return child == parent || strings.HasPrefix(child, parent+"/")
}

func includePaths(sites []Site) []string {
	var paths []string
	for _, s := range sites {
		paths = append(paths, s.IncludeFile)
	}
	return paths
}

func (c *Config) Site(id string) (Site, bool) {
	for _, s := range c.Sites {
		if s.ID == id {
			return s, true
		}
	}
	return Site{}, false
}

func (c *Config) OperationTimeout() time.Duration {
	// Includes the forward transaction, rollback, and a small RPC margin.
	return time.Duration(4*c.Nginx.CommandTimeoutSeconds+3*c.ProbeTimeoutSeconds+10) * time.Second
}

// CheckTrusted rejects writable or symlinked paths before a privileged helper
// uses them. Missing tail components are allowed for new state/include paths.
func CheckTrusted(path string) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	path = absolute
	for current := path; current != ""; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err == nil {
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok || stat.Uid != 0 || info.Mode().Perm()&0022 != 0 || info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("privileged path %s must be root-owned, not group/world writable, and not a symlink", current)
			}
		} else if !os.IsNotExist(err) {
			return err
		}
		if current == "/" {
			break
		}
	}
	return nil
}

func (c *Config) CheckPrivilegedPaths(configPath string) error {
	paths := []string{configPath, c.DeployStateDir, filepath.Dir(c.SocketPath), c.Nginx.Binary, c.Nginx.Config, c.Nginx.Prefix}
	paths = append(paths, includePaths(c.Sites)...)
	for _, s := range c.Sites {
		if s.CAFile != "" {
			paths = append(paths, s.CAFile)
		}
	}
	for _, path := range paths {
		if err := CheckTrusted(path); err != nil {
			return err
		}
	}
	return nil
}
