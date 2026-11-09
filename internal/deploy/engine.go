package deploy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"syscall"
	"time"

	"anbridge/internal/atomicfile"
	"anbridge/internal/certificate"
	"anbridge/internal/config"
	"anbridge/internal/nginx"
)

var ErrBusy = errors.New("another certificate deployment is in progress")
var versionID = regexp.MustCompile(`^[a-f0-9]{64}$`)

const MaxCertID int64 = 1<<53 - 1 // Exact in AllinSSL's JSON float64 decoder.

type Request struct {
	SiteID string `json:"site_id"`
	CertID int64  `json:"cert_id"`
	Cert   string `json:"crt"`
	Key    string `json:"key"`
}

type Active struct {
	Version          string    `json:"version"`
	Fingerprint      string    `json:"fingerprint"`
	ChainFingerprint string    `json:"chain_fingerprint"`
	CertID           int64     `json:"cert_id"`
	NotAfter         time.Time `json:"not_after"`
	VerifiedAt       time.Time `json:"verified_at"`
}

type Pending struct {
	Previous Active `json:"previous"`
	Next     Active `json:"next"`
}

type State struct {
	Active  Active   `json:"active"`
	Pending *Pending `json:"pending,omitempty"`
}

type Result struct {
	SiteID    string `json:"site_id"`
	Active    Active `json:"active"`
	Unchanged bool   `json:"unchanged"`
}

type Status struct {
	SiteID string `json:"site_id"`
	Ready  bool   `json:"ready"`
	State  State  `json:"state"`
}

type Engine struct {
	cfg        *config.Config
	driver     nginx.Driver
	log        *slog.Logger
	lock       *os.File
	mu         sync.Mutex
	writeState func(string, []byte, os.FileMode) error
}

func Open(cfg *config.Config, driver nginx.Driver, logger *slog.Logger) (*Engine, error) {
	if err := atomicfile.PrivateDir(cfg.DeployStateDir); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(cfg.DeployStateDir, "engine.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, errors.New("another deploy helper or bootstrap process owns the state directory")
	}
	if logger == nil {
		logger = slog.Default()
	}
	e := &Engine{cfg: cfg, driver: driver, log: logger, lock: f, writeState: atomicfile.Write}
	for _, site := range cfg.Sites {
		if err := atomicfile.PrivateDir(e.siteDir(site.ID)); err != nil {
			e.Close()
			return nil, err
		}
		if err := atomicfile.PrivateDir(filepath.Join(e.siteDir(site.ID), "versions")); err != nil {
			e.Close()
			return nil, err
		}
	}
	return e, nil
}

func (e *Engine) Close() error {
	if e.lock == nil {
		return nil
	}
	_ = syscall.Flock(int(e.lock.Fd()), syscall.LOCK_UN)
	err := e.lock.Close()
	e.lock = nil
	return err
}

func (e *Engine) siteDir(id string) string   { return filepath.Join(e.cfg.DeployStateDir, id) }
func (e *Engine) statePath(id string) string { return filepath.Join(e.siteDir(id), "state.json") }

func (e *Engine) readState(id string) (State, error) {
	var state State
	data, err := atomicfile.ReadRegular(e.statePath(id), 64*1024)
	if os.IsNotExist(err) {
		return state, nil
	}
	if err != nil {
		return state, err
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return state, err
	}
	if state.Active.Version != "" && !versionID.MatchString(state.Active.Version) {
		return state, errors.New("invalid active version in local state")
	}
	if state.Pending != nil && (!versionID.MatchString(state.Pending.Previous.Version) || !versionID.MatchString(state.Pending.Next.Version)) {
		return state, errors.New("invalid transaction journal")
	}
	return state, nil
}

func (e *Engine) saveState(id string, state State) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return e.writeState(e.statePath(id), append(data, '\n'), 0600)
}

func (e *Engine) include(site config.Site, version string) []byte {
	dir := filepath.Join(e.siteDir(site.ID), "versions", version)
	return []byte("# Managed by ANBridge. Do not edit.\n" +
		"ssl_certificate " + filepath.Join(dir, "fullchain.pem") + ";\n" +
		"ssl_certificate_key " + filepath.Join(dir, "privkey.pem") + ";\n")
}

func (e *Engine) store(site config.Site, bundle *certificate.Bundle) error {
	dir := filepath.Join(e.siteDir(site.ID), "versions", bundle.Version)
	if _, err := os.Lstat(dir); err == nil {
		for name, expected := range map[string][]byte{"fullchain.pem": bundle.CertPEM, "privkey.pem": bundle.KeyPEM} {
			actual, err := atomicfile.ReadRegular(filepath.Join(dir, name), certificate.MaxPEMBytes)
			if err != nil || !bytes.Equal(actual, expected) {
				return errors.New("existing immutable certificate version is incomplete or differs")
			}
		}
		parent, err := os.Open(filepath.Dir(dir))
		if err != nil {
			return err
		}
		defer parent.Close()
		return parent.Sync()
	} else if !os.IsNotExist(err) {
		return err
	}
	// Publish the complete version directory only after both files are durable.
	parent := filepath.Dir(dir)
	tmp, err := os.MkdirTemp(parent, ".version-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	if err = atomicfile.Write(filepath.Join(tmp, "fullchain.pem"), bundle.CertPEM, 0644); err != nil {
		return err
	}
	if err = atomicfile.Write(filepath.Join(tmp, "privkey.pem"), bundle.KeyPEM, 0600); err != nil {
		return err
	}
	if err = os.Rename(tmp, dir); err != nil {
		return err
	}
	f, err := os.Open(parent)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func (e *Engine) parse(site config.Site, cert, key []byte) (*certificate.Bundle, error) {
	return certificate.Parse(cert, key, site, time.Now(), time.Duration(e.cfg.MinValidityHours)*time.Hour)
}

// Bootstrap seeds a recoverable baseline. It neither edits a virtual host nor
// reloads Nginx. The operator must include the generated file and verify it.
func (e *Engine) Bootstrap(siteID string, cert, key []byte) (Active, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	site, ok := e.cfg.Site(siteID)
	if !ok {
		return Active{}, errors.New("unknown site")
	}
	state, err := e.readState(site.ID)
	if err != nil {
		return Active{}, err
	}
	if state.Active.Version != "" || state.Pending != nil {
		return Active{}, errors.New("site is already initialized; bootstrap will not overwrite it")
	}
	bundle, err := e.parse(site, cert, key)
	if err != nil {
		return Active{}, err
	}
	if _, err := os.Lstat(site.IncludeFile); err == nil {
		return Active{}, errors.New("include file already exists; bootstrap will not overwrite it")
	} else if !os.IsNotExist(err) {
		return Active{}, err
	}
	if err := os.MkdirAll(filepath.Dir(site.IncludeFile), 0750); err != nil {
		return Active{}, err
	}
	if err := e.store(site, bundle); err != nil {
		return Active{}, err
	}
	if err := atomicfile.Write(site.IncludeFile, e.include(site, bundle.Version), 0640); err != nil {
		return Active{}, err
	}
	active := Active{Version: bundle.Version, Fingerprint: bundle.Fingerprint, ChainFingerprint: bundle.ChainFingerprint, NotAfter: bundle.NotAfter}
	if err := e.saveState(site.ID, State{Active: active}); err != nil {
		return Active{}, fmt.Errorf("bootstrap state write failed; inspect generated include before retrying: %w", err)
	}
	return active, nil
}

func (e *Engine) Status(siteID string) (Status, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.cfg.Site(siteID); !ok {
		return Status{}, errors.New("unknown site")
	}
	state, err := e.readState(siteID)
	return Status{SiteID: siteID, Ready: state.Active.Version != "" && state.Pending == nil, State: state}, err
}

// Recover conservatively restores the previous committed version. Run before
// exposing the helper socket. An unrecoverable journal blocks startup.
func (e *Engine) Recover(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, site := range e.cfg.Sites {
		state, err := e.readState(site.ID)
		if err != nil {
			return err
		}
		if state.Pending == nil {
			continue
		}
		e.log.Warn("recovering unfinished deployment", "site", site.ID)
		if err := e.rollback(ctx, site, state, true); err != nil {
			return fmt.Errorf("recovery for %s failed; journal retained: %w", site.ID, err)
		}
	}
	return nil
}

// Activate deliberately owns its context: an HTTP disconnect must not interrupt
// a transaction halfway through replacing configuration or rolling back.
func (e *Engine) Activate(req Request) (Result, error) {
	if !e.mu.TryLock() {
		return Result{}, ErrBusy
	}
	defer e.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), e.cfg.OperationTimeout())
	defer cancel()
	site, ok := e.cfg.Site(req.SiteID)
	if !ok || req.CertID < 1 || req.CertID > MaxCertID {
		return Result{}, errors.New("unknown site or invalid certificate ID")
	}
	bundle, err := e.parse(site, []byte(req.Cert), []byte(req.Key))
	if err != nil {
		return Result{}, err
	}
	state, err := e.readState(site.ID)
	if err != nil {
		return Result{}, err
	}
	if state.Pending != nil {
		return Result{}, errors.New("unfinished deployment requires helper recovery")
	}
	if state.Active.Version == "" {
		return Result{}, errors.New("site must be bootstrapped with a working certificate before deployment")
	}
	actual, err := atomicfile.ReadRegular(site.IncludeFile, 64*1024)
	if err != nil || !bytes.Equal(actual, e.include(site, state.Active.Version)) {
		return Result{}, errors.New("managed include differs from committed state; refusing to overwrite external changes")
	}
	if state.Active.Version == bundle.Version {
		if err := e.driver.Verify(ctx, site, bundle.Fingerprint, bundle.ChainFingerprint); err == nil {
			state.Active.CertID = req.CertID
			state.Active.VerifiedAt = time.Now().UTC()
			if err := e.saveState(site.ID, state); err != nil {
				return Result{}, err
			}
			return Result{SiteID: site.ID, Active: state.Active, Unchanged: true}, nil
		}
	}
	if err := e.store(site, bundle); err != nil {
		return Result{}, err
	}
	next := Active{Version: bundle.Version, Fingerprint: bundle.Fingerprint, ChainFingerprint: bundle.ChainFingerprint, CertID: req.CertID, NotAfter: bundle.NotAfter}
	state.Pending = &Pending{Previous: state.Active, Next: next}
	if err := e.saveState(site.ID, state); err != nil {
		return Result{}, err
	}
	fail := func(cause error, reload bool) (Result, error) {
		e.log.Error("deployment failed", "site", site.ID, "cert_id", req.CertID, "error", cause)
		// Give rollback its own bounded budget even if the forward attempt timed out.
		rctx, rcancel := context.WithTimeout(context.Background(), e.cfg.OperationTimeout())
		defer rcancel()
		if err := e.rollback(rctx, site, state, reload); err != nil {
			e.log.Error("rollback incomplete; journal retained", "site", site.ID, "error", err)
			return Result{}, fmt.Errorf("deployment failed and rollback is incomplete; operator recovery required: %w", err)
		}
		return Result{}, fmt.Errorf("deployment failed; previous certificate restored: %w", cause)
	}
	if err := atomicfile.Write(site.IncludeFile, e.include(site, next.Version), 0640); err != nil {
		return fail(err, false)
	}
	if err := e.driver.Test(ctx); err != nil {
		return fail(err, false)
	}
	if err := e.driver.Reload(ctx); err != nil {
		// A command error can be ambiguous: assume the master may have received it.
		return fail(err, true)
	}
	if err := e.driver.Verify(ctx, site, next.Fingerprint, next.ChainFingerprint); err != nil {
		return fail(err, true)
	}
	next.VerifiedAt = time.Now().UTC()
	if err := e.saveState(site.ID, State{Active: next}); err != nil {
		// Rename may already have published the committed state before a directory
		// fsync error. Do not roll the include back blindly: that could leave
		// committed-new state paired with old configuration after a crash.
		// Keeping the new include is recoverable in both cases: a retained pending
		// journal rolls back on startup; a published commit already matches it.
		e.log.Error("new certificate verified but commit durability is uncertain",
			"site", site.ID, "error", err)
		return Result{}, fmt.Errorf("new certificate is serving but state commit failed; inspect status and storage before retrying: %w", err)
	}
	e.log.Info("certificate deployed and verified", "site", site.ID, "cert_id", req.CertID,
		"fingerprint", next.Fingerprint, "not_after", next.NotAfter)
	return Result{SiteID: site.ID, Active: next}, nil
}

func (e *Engine) rollback(ctx context.Context, site config.Site, state State, reload bool) error {
	if state.Pending == nil {
		return errors.New("no pending transaction")
	}
	previous := state.Pending.Previous
	if err := atomicfile.Write(site.IncludeFile, e.include(site, previous.Version), 0640); err != nil {
		return err
	}
	if reload {
		if err := e.driver.Test(ctx); err != nil {
			return err
		}
		if err := e.driver.Reload(ctx); err != nil {
			return err
		}
	}
	if err := e.driver.Verify(ctx, site, previous.Fingerprint, previous.ChainFingerprint); err != nil {
		return fmt.Errorf("previous certificate could not be verified: %w", err)
	}
	previous.VerifiedAt = time.Now().UTC()
	if err := e.saveState(site.ID, State{Active: previous}); err != nil {
		return err
	}
	e.log.Warn("previous certificate restored and verified", "site", site.ID, "fingerprint", previous.Fingerprint)
	return nil
}
