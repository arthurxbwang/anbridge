// Package api implements the subset of the SafeLine panel API used by AllinSSL.
package api

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"anbridge/internal/atomicfile"
	"anbridge/internal/certificate"
	"anbridge/internal/config"
	"anbridge/internal/deploy"
	"anbridge/internal/helper"
)

const TokenHeader = "X-SLCE-API-TOKEN"
const MaxBodyBytes = 384 * 1024

type identity struct {
	site config.Site
	hash [32]byte
}

type staged struct {
	ID        int64     `json:"id"`
	SiteID    string    `json:"site_id"`
	Cert      string    `json:"crt"`
	Key       string    `json:"key"`
	CreatedAt time.Time `json:"created_at"`
}

type Server struct {
	cfg        *config.Config
	backend    helper.Backend
	identities []identity
	log        *slog.Logger
	mu         sync.Mutex
}

func New(cfg *config.Config, backend helper.Backend, logger *slog.Logger) (*Server, error) {
	if err := atomicfile.PrivateDir(cfg.APIStateDir); err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}
	s := &Server{cfg: cfg, backend: backend, log: logger}
	hashes := map[[32]byte]bool{}
	for _, site := range cfg.Sites {
		info, err := os.Lstat(site.TokenFile)
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0007 != 0 {
			return nil, fmt.Errorf("token file for %s must be regular and not accessible to other users", site.ID)
		}
		data, err := atomicfile.ReadRegular(site.TokenFile, 4096)
		if err != nil {
			return nil, err
		}
		token := strings.TrimSpace(string(data))
		if len(token) < 32 || strings.ContainsAny(token, "\r\n\t ") {
			return nil, fmt.Errorf("token for %s must have at least 32 non-whitespace characters", site.ID)
		}
		hash := sha256.Sum256([]byte(token))
		if hashes[hash] {
			return nil, errors.New("tokens must be unique per site")
		}
		hashes[hash] = true
		s.identities = append(s.identities, identity{site: site, hash: hash})
		if err := atomicfile.PrivateDir(filepath.Join(cfg.APIStateDir, site.ID)); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func respond(w http.ResponseWriter, code int, data any, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	// AllinSSL 1.1.4 asserts msg is a string, including on successful responses.
	_ = json.NewEncoder(w).Encode(struct {
		Data any    `json:"data"`
		Msg  string `json:"msg"`
	}{data, msg})
}

func decode(w http.ResponseWriter, r *http.Request, dst any) error {
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxBodyBytes))
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return errors.New("unexpected trailing JSON")
	}
	return nil
}

func (s *Server) authenticate(r *http.Request) (config.Site, bool) {
	candidate := sha256.Sum256([]byte(r.Header.Get(TokenHeader)))
	var found config.Site
	matched := 0
	for _, identity := range s.identities {
		same := subtle.ConstantTimeCompare(candidate[:], identity.hash[:])
		matched |= same
		if same == 1 {
			found = identity.site
		}
	}
	return found, matched == 1
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" && r.Method == http.MethodGet {
		respond(w, http.StatusOK, map[string]string{"service": "anbridge", "status": "alive"}, "")
		return
	}
	site, ok := s.authenticate(r)
	if !ok {
		respond(w, http.StatusUnauthorized, nil, "unauthorized")
		return
	}
	switch {
	case r.URL.Path == "/api/open/site/group" && r.Method == http.MethodGet:
		// Only the authorized target is visible; there is no site management API.
		respond(w, http.StatusOK, []any{map[string]any{"id": 1, "name": site.ID}}, "")
	case r.URL.Path == "/api/open/cert" && r.Method == http.MethodPost:
		s.upload(w, r, site)
	case r.URL.Path == "/api/open/system" && r.Method == http.MethodPut:
		s.bind(w, r, site)
	case r.URL.Path == "/api/open/system" && r.Method == http.MethodGet:
		status, err := s.backend.Status(site.ID)
		if err != nil {
			s.log.Error("status unavailable", "site", site.ID, "error", err)
			respond(w, http.StatusServiceUnavailable, nil, "deployment helper unavailable")
			return
		}
		respond(w, http.StatusOK, status, "")
	default:
		respond(w, http.StatusNotFound, nil, "unsupported endpoint or method")
	}
}

func (s *Server) upload(w http.ResponseWriter, r *http.Request, site config.Site) {
	var req struct {
		Type int    `json:"type"`
		Cert string `json:"crt"`
		Key  string `json:"key"`
		ID   int64  `json:"id,omitempty"`
	}
	if err := decode(w, r, &req); err != nil || req.Type != 2 || req.ID != 0 {
		respond(w, http.StatusBadRequest, nil, "expected a manual certificate upload with type=2")
		return
	}
	bundle, err := certificate.Parse([]byte(req.Cert), []byte(req.Key), site, time.Now(), time.Duration(s.cfg.MinValidityHours)*time.Hour)
	if err != nil {
		respond(w, http.StatusBadRequest, nil, err.Error())
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	dir := filepath.Join(s.cfg.APIStateDir, site.ID)
	count, err := s.prune(dir)
	if err != nil {
		s.log.Error("staging cleanup failed", "site", site.ID, "error", err)
		respond(w, http.StatusInternalServerError, nil, "certificate staging unavailable")
		return
	}
	if count >= s.cfg.MaxStagedPerSite {
		respond(w, http.StatusTooManyRequests, nil, "staged certificate quota reached; wait for expiration or remove obsolete staging files locally")
		return
	}
	var id int64
	for attempt := 0; attempt < 8; attempt++ {
		var random [8]byte
		if _, err := rand.Read(random[:]); err != nil {
			respond(w, http.StatusInternalServerError, nil, "certificate ID generation failed")
			return
		}
		id = int64(binary.BigEndian.Uint64(random[:]) & uint64(deploy.MaxCertID))
		if id == 0 {
			continue
		}
		if _, err := os.Lstat(filepath.Join(dir, strconv.FormatInt(id, 10)+".json")); os.IsNotExist(err) {
			break
		}
		id = 0
	}
	if id == 0 {
		respond(w, http.StatusInternalServerError, nil, "certificate ID generation failed")
		return
	}
	entry := staged{ID: id, SiteID: site.ID, Cert: string(bundle.CertPEM), Key: string(bundle.KeyPEM), CreatedAt: time.Now().UTC()}
	data, err := json.Marshal(entry)
	if err == nil {
		err = atomicfile.Write(filepath.Join(dir, strconv.FormatInt(id, 10)+".json"), data, 0600)
	}
	if err != nil {
		s.log.Error("certificate staging failed", "site", site.ID, "error", err)
		respond(w, http.StatusInternalServerError, nil, "certificate staging failed")
		return
	}
	s.log.Info("certificate staged", "site", site.ID, "cert_id", id, "fingerprint", bundle.Fingerprint)
	// AllinSSL expects {"data": <number>, "msg": ""}, not {"data":{"id":...}}.
	respond(w, http.StatusOK, id, "")
}

func (s *Server) prune(dir string) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		data, err := atomicfile.ReadRegular(path, MaxBodyBytes)
		if err != nil {
			return count, err
		}
		var item staged
		if err := json.Unmarshal(data, &item); err != nil {
			return count, errors.New("invalid staged certificate state")
		}
		if time.Since(item.CreatedAt) > time.Duration(s.cfg.StagedTTLHours)*time.Hour {
			if err := os.Remove(path); err != nil {
				return count, err
			}
		} else {
			count++
		}
	}
	return count, nil
}

func (s *Server) bind(w http.ResponseWriter, r *http.Request, site config.Site) {
	var req struct {
		CertID int64 `json:"cert_id"`
	}
	if err := decode(w, r, &req); err != nil || req.CertID < 1 || req.CertID > deploy.MaxCertID {
		respond(w, http.StatusBadRequest, nil, "invalid cert_id")
		return
	}
	s.mu.Lock()
	data, err := atomicfile.ReadRegular(filepath.Join(s.cfg.APIStateDir, site.ID, strconv.FormatInt(req.CertID, 10)+".json"), MaxBodyBytes)
	s.mu.Unlock()
	if err != nil {
		respond(w, http.StatusNotFound, nil, "certificate not found for this deployment identity")
		return
	}
	var item staged
	if err := json.Unmarshal(data, &item); err != nil || item.ID != req.CertID || item.SiteID != site.ID ||
		time.Since(item.CreatedAt) > time.Duration(s.cfg.StagedTTLHours)*time.Hour {
		respond(w, http.StatusBadRequest, nil, "invalid or expired staged certificate")
		return
	}
	result, err := s.backend.Activate(deploy.Request{SiteID: site.ID, CertID: item.ID, Cert: item.Cert, Key: item.Key})
	if err != nil {
		s.log.Error("certificate activation failed", "site", site.ID, "cert_id", item.ID, "error", err)
		if errors.Is(err, deploy.ErrBusy) {
			respond(w, http.StatusConflict, nil, "another deployment is in progress; retry binding")
		} else {
			respond(w, http.StatusBadGateway, nil, "activation failed; inspect local deployment logs and status before retrying")
		}
		return
	}
	respond(w, http.StatusOK, result, "")
}
