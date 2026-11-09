package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"anbridge/internal/config"
	"anbridge/internal/testutil"
)

func TestRejectUnsafeConfiguration(t *testing.T) {
	for _, kind := range []string{"path injection", "path traversal", "remote probe", "missing probe", "duplicate token path", "nested state"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			pki := testutil.NewPKI(t, dir)
			cfg := testutil.Config(t, dir, pki, "zabbix", "api")
			switch kind {
			case "path injection":
				cfg.Sites[0].IncludeFile += ";return"
			case "path traversal":
				cfg.Sites[0].IncludeFile = dir + "/includes/../site.conf"
			case "remote probe":
				cfg.Sites[0].Probes[0].Address = "192.0.2.1:443"
			case "missing probe":
				cfg.Sites[0].Domains = append(cfg.Sites[0].Domains, "extra.example.test")
			case "duplicate token path":
				cfg.Sites[1].TokenFile = cfg.Sites[0].TokenFile
			case "nested state":
				cfg.DeployStateDir = cfg.APIStateDir + "/helper"
			}
			if err := cfg.Validate(); err == nil {
				t.Fatal("unsafe configuration was accepted")
			}
		})
	}
}

func TestPrivilegedPathTrust(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("ownership checks require a root-owned test hierarchy")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "helper.json")
	if err := os.WriteFile(path, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := config.CheckTrusted(path); err != nil {
		// This also catches developer environments with group-writable ancestors.
		t.Skipf("test parent is not a trusted root-owned hierarchy: %v", err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	relative, err := filepath.Rel(cwd, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := config.CheckTrusted(relative); err != nil {
		t.Fatalf("relative CLI config path was not resolved safely: %v", err)
	}
	if err := os.Chmod(path, 0660); err != nil {
		t.Fatal(err)
	}
	if err := config.CheckTrusted(path); err == nil {
		t.Fatal("group-writable privileged config accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "linked.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := config.CheckTrusted(link); err == nil {
		t.Fatal("symlinked privileged config accepted")
	}
	if err := os.Chown(path, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if err := config.CheckTrusted(path); err == nil {
		t.Fatal("non-root-owned privileged config accepted")
	}
}
