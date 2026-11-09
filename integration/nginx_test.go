package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"anbridge/internal/api"
	"anbridge/internal/certificate"
	"anbridge/internal/deploy"
	"anbridge/internal/helper"
	"anbridge/internal/nginx"
	"anbridge/internal/testutil"
)

type countingDriver struct {
	*nginx.Local
	reloads atomic.Int32
}

func (d *countingDriver) Reload(ctx context.Context) error {
	d.reloads.Add(1)
	return d.Local.Reload(ctx)
}

func TestRealNginxThroughHTTPSAndUnixHelper(t *testing.T) {
	if os.Getenv("ANBRIDGE_INTEGRATION") != "1" {
		t.Skip("set ANBRIDGE_INTEGRATION=1 and NGINX_BIN to run real Nginx integration")
	}
	binary := os.Getenv("NGINX_BIN")
	if binary == "" {
		t.Fatal("NGINX_BIN is required")
	}
	if _, err := os.Stat(binary); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	pki := testutil.NewPKI(t, dir)
	cfg := testutil.Config(t, dir, pki, "zabbix")
	cfg.Nginx.Binary = binary
	cfg.SocketPath = filepath.Join(dir, "rpc.sock")
	// Linux Unix socket paths are limited to 108 bytes.
	if len(cfg.SocketPath) >= 104 {
		short, err := os.MkdirTemp(os.Getenv("TMPDIR"), "rpc-")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.RemoveAll(short) })
		cfg.SocketPath = filepath.Join(short, "helper.sock")
	}
	cfg.ProbeTimeoutSeconds = 3
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	cfg.Sites[0].Probes[0].Address = address
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	driver := &countingDriver{Local: &nginx.Local{Config: cfg.Nginx, ProbeTimeout: 3 * time.Second}}
	engine, err := deploy.Open(cfg, driver, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	oldCert, oldKey := pki.Issue(t, cfg.Sites[0].Domains, nil)
	old, err := engine.Bootstrap("zabbix", oldCert, oldKey)
	if err != nil {
		t.Fatal(err)
	}
	pidFile := filepath.Join(dir, "nginx.pid")
	configText := fmt.Sprintf(`pid %s;
error_log %s info;
worker_processes 1;
events { worker_connections 64; }
http {
  access_log off;
  client_body_temp_path %s;
  proxy_temp_path %s;
  fastcgi_temp_path %s;
  uwsgi_temp_path %s;
  scgi_temp_path %s;
  server {
    listen %s ssl;
    server_name zabbix.example.test;
    include %s;
    location / { return 200 "anbridge integration\n"; }
  }
}
`, pidFile, filepath.Join(dir, "nginx-error.log"),
		filepath.Join(dir, "client-temp"), filepath.Join(dir, "proxy-temp"),
		filepath.Join(dir, "fastcgi-temp"), filepath.Join(dir, "uwsgi-temp"),
		filepath.Join(dir, "scgi-temp"), address, cfg.Sites[0].IncludeFile)
	writeConfig := func(text string) {
		t.Helper()
		if err := os.WriteFile(cfg.Nginx.Config, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeConfig(configText)
	cmd := exec.Command(binary, "-p", dir, "-c", cfg.Nginx.Config)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("start nginx: %v: %s", err, output)
	}
	t.Cleanup(func() {
		command := exec.Command(binary, "-p", dir, "-c", cfg.Nginx.Config, "-s", "quit")
		if output, err := command.CombinedOutput(); err != nil {
			t.Errorf("stop isolated nginx: %v: %s", err, output)
		}
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(pidFile); os.IsNotExist(err) {
				return
			}
			time.Sleep(25 * time.Millisecond)
		}
		t.Error("isolated nginx did not exit")
	})
	if err := driver.Verify(context.Background(), cfg.Sites[0], old.Fingerprint, old.ChainFingerprint); err != nil {
		t.Fatal(err)
	}
	unixListener, err := helper.Listen(cfg.SocketPath, "")
	if err != nil {
		t.Fatal(err)
	}
	helperServer := &http.Server{Handler: helper.Handler(engine)}
	go helperServer.Serve(unixListener)
	t.Cleanup(func() { helperServer.Close(); unixListener.Close() })
	handler, err := api.New(cfg, helper.NewClient(cfg), logger)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	client := server.Client()
	call := func(method, path string, payload any) (int, map[string]any) {
		t.Helper()
		var body []byte
		if payload != nil {
			body, _ = json.Marshal(payload)
		}
		request, err := http.NewRequest(method, server.URL+path, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set(api.TokenHeader, testutil.Token("zabbix"))
		request.Header.Set("Content-Type", "application/json")
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		var result map[string]any
		if err := json.NewDecoder(io.LimitReader(response.Body, 64*1024)).Decode(&result); err != nil {
			t.Fatal(err)
		}
		if _, ok := result["msg"].(string); !ok {
			t.Fatal("missing AllinSSL msg field")
		}
		return response.StatusCode, result
	}
	newCert, newKey := pki.Issue(t, cfg.Sites[0].Domains, nil)
	bundle, err := certificate.Parse(newCert, newKey, cfg.Sites[0], time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	upload := func(cert, key []byte) int64 {
		t.Helper()
		code, response := call("POST", "/api/open/cert", map[string]any{"type": 2, "crt": string(cert), "key": string(key)})
		if code != 200 || response["msg"] != "" {
			t.Fatalf("upload: %d %v", code, response)
		}
		return int64(response["data"].(float64))
	}
	bind := func(id int64) (int, map[string]any) {
		return call("PUT", "/api/open/system", map[string]any{"cert_id": id})
	}
	code, result := call("GET", "/api/open/site/group", nil)
	if code != 200 {
		t.Fatal(result)
	}
	id := upload(newCert, newKey)
	if err := driver.Verify(context.Background(), cfg.Sites[0], old.Fingerprint, old.ChainFingerprint); err != nil {
		t.Fatal("upload changed the live certificate before binding")
	}
	code, result = bind(id)
	if code != 200 || result["msg"] != "" {
		t.Fatalf("activation: %d %v", code, result)
	}
	if err := driver.Verify(context.Background(), cfg.Sites[0], bundle.Fingerprint, bundle.ChainFingerprint); err != nil {
		t.Fatal(err)
	}
	t.Log("real Nginx served the renewed certificate after AllinSSL-compatible upload/bind")
	shortProbe := *driver.Local
	shortProbe.ProbeTimeout = 300 * time.Millisecond
	if err := shortProbe.Verify(context.Background(), cfg.Sites[0], bundle.Fingerprint, strings.Repeat("0", 64)); err == nil {
		t.Fatal("matching leaf with the wrong chain identity was accepted")
	}
	previousReloads := driver.reloads.Load()
	code, result = bind(id)
	if code != 200 || driver.reloads.Load() != previousReloads {
		t.Fatalf("idempotent retry reloaded nginx: %v", result)
	}
	t.Log("repeated binding verified the current certificate without another reload")

	// A separately broken operator config must not be overwritten or reloaded.
	thirdCert, thirdKey := pki.Issue(t, cfg.Sites[0].Domains, nil)
	thirdID := upload(thirdCert, thirdKey)
	writeConfig(configText + "\nanbridge_invalid_directive;\n")
	code, result = bind(thirdID)
	if code == 200 || result["msg"] == "" {
		t.Fatal("invalid nginx config accepted")
	}
	if err := driver.Verify(context.Background(), cfg.Sites[0], bundle.Fingerprint, bundle.ChainFingerprint); err != nil {
		t.Fatal("old runtime was lost after failed -t")
	}
	writeConfig(configText)
	status, err := engine.Status("zabbix")
	if err != nil || status.State.Pending != nil || status.State.Active.Version != bundle.Version {
		t.Fatalf("rollback state: %+v %v", status, err)
	}
	t.Log("nginx -t failure preserved the working certificate and restored its include")

	// Nginx can accept a reload while the intended vhost ignores the managed file.
	// Simulate that by directly referencing the current immutable certificate.
	managed, err := os.ReadFile(cfg.Sites[0].IncludeFile)
	if err != nil {
		t.Fatal(err)
	}
	detached := strings.Replace(configText, "include "+cfg.Sites[0].IncludeFile+";", string(managed), 1)
	writeConfig(detached)
	code, result = bind(thirdID)
	if code == 200 || result["msg"] == "" {
		t.Fatal("reload-only success was incorrectly accepted")
	}
	if err := driver.Verify(context.Background(), cfg.Sites[0], bundle.Fingerprint, bundle.ChainFingerprint); err != nil {
		t.Fatal(err)
	}
	writeConfig(configText)
	t.Log("successful reload with the wrong live certificate was detected and rolled back")

	// Reproduce a crash after the new certificate is loaded, before commit.
	thirdBundle, err := certificate.Parse(thirdCert, thirdKey, cfg.Sites[0], time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	status, err = engine.Status("zabbix")
	if err != nil {
		t.Fatal(err)
	}
	pending := status.State
	pending.Pending = &deploy.Pending{
		Previous: pending.Active,
		Next: deploy.Active{
			Version: thirdBundle.Version, Fingerprint: thirdBundle.Fingerprint,
			ChainFingerprint: thirdBundle.ChainFingerprint, CertID: thirdID, NotAfter: thirdBundle.NotAfter,
		},
	}
	journal, err := json.Marshal(pending)
	if err != nil {
		t.Fatal(err)
	}
	stateFile := filepath.Join(cfg.DeployStateDir, "zabbix", "state.json")
	if err := os.WriteFile(stateFile, journal, 0600); err != nil {
		t.Fatal(err)
	}
	nextInclude := strings.ReplaceAll(string(managed), bundle.Version, thirdBundle.Version)
	if err := os.WriteFile(cfg.Sites[0].IncludeFile, []byte(nextInclude), 0640); err != nil {
		t.Fatal(err)
	}
	if err := driver.Test(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := driver.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := driver.Verify(context.Background(), cfg.Sites[0], thirdBundle.Fingerprint, thirdBundle.ChainFingerprint); err != nil {
		t.Fatal(err)
	}
	helperServer.Close()
	unixListener.Close()
	engine.Close()
	restarted, err := deploy.Open(cfg, driver, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if err := restarted.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := driver.Verify(context.Background(), cfg.Sites[0], bundle.Fingerprint, bundle.ChainFingerprint); err != nil {
		t.Fatal(err)
	}
	recovered, err := restarted.Status("zabbix")
	if err != nil || recovered.State.Pending != nil || recovered.State.Active.Version != bundle.Version {
		t.Fatalf("restart recovery did not restore the last committed version: %+v %v", recovered, err)
	}
	t.Log("reopened helper recovered an interrupted deployment against real Nginx")
}
