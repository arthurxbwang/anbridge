// Package testutil contains fixtures for tests; it is not used by the executable.
package testutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"anbridge/internal/config"
)

type PKI struct {
	Cert   *x509.Certificate
	Key    *ecdsa.PrivateKey
	PEM    []byte
	CAFile string
}

func NewPKI(t *testing.T, dir string) *PKI {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: serial(t), Subject: pkix.Name{CommonName: "ANBridge test root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	path := filepath.Join(dir, "root-ca.pem")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return &PKI{Cert: cert, Key: key, PEM: data, CAFile: path}
}

func serial(t *testing.T) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	return n.Add(n, big.NewInt(1))
}

func (p *PKI) Issue(t *testing.T, names []string, adjust func(*x509.Certificate)) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: serial(t), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(30 * 24 * time.Hour),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if adjust != nil {
		adjust(template)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, p.Cert, &key.PublicKey, p.Key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), p.PEM...)
	return chain, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func (p *PKI) Intermediate(t *testing.T) *PKI {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: serial(t), Subject: pkix.Name{CommonName: "ANBridge test intermediate"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, p.Cert, &key.PublicKey, p.Key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), p.PEM...)
	return &PKI{Cert: cert, Key: key, PEM: chain, CAFile: p.CAFile}
}

func Config(t *testing.T, dir string, pki *PKI, names ...string) *config.Config {
	t.Helper()
	cfg := &config.Config{
		Listen:      "127.0.0.1:9443",
		TLS:         config.TLS{CertFile: filepath.Join(dir, "api-cert.pem"), KeyFile: filepath.Join(dir, "api-key.pem")},
		APIStateDir: filepath.Join(dir, "api-state"), DeployStateDir: filepath.Join(dir, "deploy-state"),
		SocketPath: filepath.Join(dir, "helper.sock"), MinValidityHours: 1,
		ProbeTimeoutSeconds: 2,
		Nginx:               config.Nginx{Binary: "/usr/sbin/nginx", Config: filepath.Join(dir, "nginx.conf"), Prefix: dir, CommandTimeoutSeconds: 5},
	}
	for _, name := range names {
		token := filepath.Join(dir, name+".token")
		if err := os.WriteFile(token, []byte(Token(name)), 0600); err != nil {
			t.Fatal(err)
		}
		cfg.Sites = append(cfg.Sites, config.Site{
			ID: name, TokenFile: token, Domains: []string{name + ".example.test"}, CAFile: pki.CAFile,
			IncludeFile: filepath.Join(dir, "includes", name+".conf"),
			Probes:      []config.Probe{{Address: "127.0.0.1:18443", ServerName: name + ".example.test"}},
		})
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func Token(site string) string { return "test-only-not-a-production-token-1234567890-" + site }
