package deploy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"anbridge/internal/atomicfile"
	"anbridge/internal/certificate"
	"anbridge/internal/config"
	"anbridge/internal/testutil"
)

type fakeDriver struct {
	mu          sync.Mutex
	tests       int
	reloads     int
	testErr     bool
	reloadFails map[int]bool
	failVerify  string
	served      string
	target      string
	previous    string
	gate        chan struct{}
	entered     chan struct{}
}

func (d *fakeDriver) Test(ctx context.Context) error {
	d.mu.Lock()
	d.tests++
	fail, gate, entered := d.testErr, d.gate, d.entered
	d.mu.Unlock()
	if entered != nil {
		select {
		case entered <- struct{}{}:
		default:
		}
	}
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if fail {
		return errors.New("injected config failure")
	}
	return nil
}
func (d *fakeDriver) Reload(context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.reloads++
	if d.reloadFails[d.reloads] {
		return errors.New("injected reload failure")
	}
	if d.reloads == 1 {
		d.served = d.target
	} else {
		d.served = d.previous
	}
	return nil
}
func (d *fakeDriver) Verify(_ context.Context, _ config.Site, fingerprint, _ string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if fingerprint == d.failVerify || d.served != fingerprint {
		return errors.New("injected certificate mismatch")
	}
	return nil
}

type fixture struct {
	cfg    *config.Config
	engine *Engine
	driver *fakeDriver
	old    Active
	next   *certificate.Bundle
}

func setup(t *testing.T) fixture {
	t.Helper()
	dir := t.TempDir()
	pki := testutil.NewPKI(t, dir)
	cfg := testutil.Config(t, dir, pki, "zabbix")
	oldCert, oldKey := pki.Issue(t, cfg.Sites[0].Domains, nil)
	nextCert, nextKey := pki.Issue(t, cfg.Sites[0].Domains, nil)
	bundle, err := certificate.Parse(nextCert, nextKey, cfg.Sites[0], time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	driver := &fakeDriver{reloadFails: map[int]bool{}, target: bundle.Fingerprint}
	engine, err := Open(cfg, driver, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { engine.Close() })
	old, err := engine.Bootstrap("zabbix", oldCert, oldKey)
	if err != nil {
		t.Fatal(err)
	}
	driver.previous, driver.served = old.Fingerprint, old.Fingerprint
	return fixture{cfg, engine, driver, old, bundle}
}

func (f fixture) request() Request {
	return Request{SiteID: "zabbix", CertID: 123, Cert: string(f.next.CertPEM), Key: string(f.next.KeyPEM)}
}

func TestActivateAndIdempotentRetry(t *testing.T) {
	f := setup(t)
	result, err := f.engine.Activate(f.request())
	if err != nil || result.Active.Fingerprint != f.next.Fingerprint || result.Unchanged {
		t.Fatalf("deploy: %+v %v", result, err)
	}
	req := f.request()
	req.CertID = 124
	repeated, err := f.engine.Activate(req)
	if err != nil || !repeated.Unchanged || f.driver.reloads != 1 || repeated.Active.CertID != 124 {
		t.Fatalf("retry must not reload an already served certificate: %+v %v", repeated, err)
	}
	status, err := f.engine.Status("zabbix")
	if err != nil || status.State.Pending != nil || !status.Ready {
		t.Fatalf("invalid committed state: %+v %v", status, err)
	}
	info, err := os.Stat(filepath.Join(f.engine.siteDir("zabbix"), "versions", f.next.Version, "privkey.pem"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("private key permissions: %v %v", info, err)
	}
}

func TestDeploymentFailuresRestorePreviousCertificate(t *testing.T) {
	for _, mode := range []string{"configuration", "reload", "TLS verification"} {
		t.Run(mode, func(t *testing.T) {
			f := setup(t)
			switch mode {
			case "configuration":
				f.driver.testErr = true
			case "reload":
				f.driver.reloadFails[1] = true
			case "TLS verification":
				f.driver.failVerify = f.next.Fingerprint
			}
			if _, err := f.engine.Activate(f.request()); err == nil {
				t.Fatal("injected failure was reported as success")
			}
			status, err := f.engine.Status("zabbix")
			if err != nil || status.State.Active.Version != f.old.Version || status.State.Pending != nil {
				t.Fatalf("previous committed state not restored: %+v %v", status, err)
			}
			data, _ := os.ReadFile(f.cfg.Sites[0].IncludeFile)
			if !bytes.Equal(data, f.engine.include(f.cfg.Sites[0], f.old.Version)) || f.driver.served != f.old.Fingerprint {
				t.Fatal("old configuration and served certificate were not restored")
			}
		})
	}
}

func TestFailedRollbackKeepsJournalAndBlocksFurtherWrites(t *testing.T) {
	f := setup(t)
	f.driver.failVerify = f.next.Fingerprint
	f.driver.reloadFails[2] = true
	if _, err := f.engine.Activate(f.request()); err == nil {
		t.Fatal("failed rollback returned success")
	}
	state, _ := f.engine.readState("zabbix")
	if state.Pending == nil {
		t.Fatal("failed rollback discarded recovery journal")
	}
	if _, err := f.engine.Activate(f.request()); err == nil {
		t.Fatal("pending journal did not block another deployment")
	}
	f.driver.failVerify = ""
	if err := f.engine.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	state, _ = f.engine.readState("zabbix")
	if state.Pending != nil || state.Active.Version != f.old.Version {
		t.Fatal("recovery did not commit previous version")
	}
}

func TestRecoveryAfterInterruptedConfigurationSwitch(t *testing.T) {
	f := setup(t)
	if err := f.engine.store(f.cfg.Sites[0], f.next); err != nil {
		t.Fatal(err)
	}
	state := State{Active: f.old, Pending: &Pending{Previous: f.old, Next: Active{Version: f.next.Version}}}
	if err := f.engine.saveState("zabbix", state); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.cfg.Sites[0].IncludeFile, f.engine.include(f.cfg.Sites[0], f.next.Version), 0640); err != nil {
		t.Fatal(err)
	}
	f.driver.reloads = 1
	f.driver.served = f.next.Fingerprint
	f.engine.Close()
	restarted, err := Open(f.cfg, f.driver, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if err := restarted.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	status, _ := restarted.Status("zabbix")
	if status.State.Pending != nil || f.driver.served != f.old.Fingerprint {
		t.Fatal("startup recovery failed")
	}
}

func TestRefusesExternalIncludeEditsAndSecondProcess(t *testing.T) {
	f := setup(t)
	if other, err := Open(f.cfg, f.driver, nil); err == nil {
		other.Close()
		t.Fatal("second process acquired engine state lock")
	}
	external := []byte("# operator modified configuration\n")
	if err := os.WriteFile(f.cfg.Sites[0].IncludeFile, external, 0640); err != nil {
		t.Fatal(err)
	}
	if _, err := f.engine.Activate(f.request()); err == nil {
		t.Fatal("external configuration edit was overwritten")
	}
	actual, _ := os.ReadFile(f.cfg.Sites[0].IncludeFile)
	if !bytes.Equal(actual, external) {
		t.Fatal("external configuration was modified")
	}
}

func TestConcurrentDeploymentReturnsBusy(t *testing.T) {
	f := setup(t)
	f.driver.gate = make(chan struct{})
	f.driver.entered = make(chan struct{}, 1)
	result := make(chan error, 1)
	go func() { _, err := f.engine.Activate(f.request()); result <- err }()
	select {
	case <-f.driver.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("deployment did not enter config test")
	}
	_, err := f.engine.Activate(f.request())
	close(f.driver.gate)
	if !errors.Is(err, ErrBusy) {
		t.Fatalf("expected busy, got %v", err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestHelperIndependentlyRejectsUntrustedRequests(t *testing.T) {
	for _, kind := range []string{"bad key", "unknown site", "invalid ID", "symlink include"} {
		t.Run(kind, func(t *testing.T) {
			f := setup(t)
			req := f.request()
			switch kind {
			case "bad key":
				req.Key = "not a private key"
			case "unknown site":
				req.SiteID = "../other"
			case "invalid ID":
				req.CertID = 0
			case "symlink include":
				target := filepath.Join(filepath.Dir(f.cfg.Sites[0].IncludeFile), "external.conf")
				if err := os.Rename(f.cfg.Sites[0].IncludeFile, target); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, f.cfg.Sites[0].IncludeFile); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := f.engine.Activate(req); err == nil {
				t.Fatal("unsafe request accepted by privileged backend")
			}
			if f.driver.reloads != 0 || f.driver.tests != 0 {
				t.Fatal("rejected request reached nginx command execution")
			}
			state, err := f.engine.readState("zabbix")
			if err != nil || state.Pending != nil || state.Active.Version != f.old.Version {
				t.Fatalf("rejected request changed committed state: %+v %v", state, err)
			}
		})
	}
}

func TestCommitWriteFailureRemainsRecoverableBeforeOrAfterRename(t *testing.T) {
	for _, afterRename := range []bool{false, true} {
		t.Run(fmt.Sprintf("after_rename_%t", afterRename), func(t *testing.T) {
			f := setup(t)
			writes := 0
			f.engine.writeState = func(path string, data []byte, mode os.FileMode) error {
				writes++
				if writes == 2 {
					if afterRename {
						if err := atomicfile.Write(path, data, mode); err != nil {
							return err
						}
					}
					return errors.New("injected state commit I/O error")
				}
				return atomicfile.Write(path, data, mode)
			}
			if _, err := f.engine.Activate(f.request()); err == nil {
				t.Fatal("uncertain durable commit reported success")
			}
			// A state rename may already have happened: do not restore the old
			// configuration behind the newly committed state's back.
			include, err := os.ReadFile(f.cfg.Sites[0].IncludeFile)
			if err != nil || !bytes.Equal(include, f.engine.include(f.cfg.Sites[0], f.next.Version)) {
				t.Fatal("ambiguous commit produced mismatched runtime/configuration")
			}
			if f.driver.served != f.next.Fingerprint {
				t.Fatal("ambiguous commit unexpectedly changed live certificate")
			}
			f.engine.writeState = atomicfile.Write
			if err := f.engine.Recover(context.Background()); err != nil {
				t.Fatal(err)
			}
			state, err := f.engine.readState("zabbix")
			if err != nil || state.Pending != nil {
				t.Fatalf("unrecovered state: %+v %v", state, err)
			}
			want := f.old.Version
			if afterRename {
				want = f.next.Version
			}
			if state.Active.Version != want {
				t.Fatalf("got %s, want %s", state.Active.Version, want)
			}
		})
	}
}
