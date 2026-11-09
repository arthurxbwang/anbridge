package certificate

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"anbridge/internal/config"
	"anbridge/internal/testutil"
)

func TestCertificateValidationAndFullChain(t *testing.T) {
	dir := t.TempDir()
	pki := testutil.NewPKI(t, dir)
	issuer := pki.Intermediate(t)
	site := config.Site{Domains: []string{"zabbix.example.test", "other.example.test"}, CAFile: pki.CAFile}
	cert, key := issuer.Issue(t, site.Domains, nil)
	bundle, err := Parse(cert, key, site, time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bundle.CertPEM, cert) || len(bundle.Version) != 64 || len(bundle.Fingerprint) != 64 {
		t.Fatal("full chain or identifiers were not preserved")
	}
	var decoded []*x509.Certificate
	remaining := cert
	for len(remaining) != 0 {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}
		parsed, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		decoded = append(decoded, parsed)
		remaining = rest
	}
	if ChainFingerprint(decoded) != ChainFingerprint(decoded[:len(decoded)-1]) {
		t.Fatal("optional root transmission changed chain identity")
	}
	if ChainFingerprint(decoded) == ChainFingerprint(decoded[:1]) {
		t.Fatal("missing intermediate was not reflected in chain identity")
	}
	leaf, _ := pem.Decode(cert)
	if _, err := Parse(pem.EncodeToMemory(leaf), key, site, time.Now(), time.Hour); err == nil {
		t.Fatal("missing intermediate certificate was accepted")
	}
	_, wrongKey := issuer.Issue(t, site.Domains, nil)
	otherDir := filepath.Join(dir, "other-ca")
	if err := os.Mkdir(otherDir, 0700); err != nil {
		t.Fatal(err)
	}
	untrusted := testutil.NewPKI(t, otherDir)
	untrustedCert, untrustedKey := untrusted.Issue(t, site.Domains, nil)
	wrongName, wrongNameKey := issuer.Issue(t, []string{"wrong.example.test"}, nil)
	expired, expiredKey := issuer.Issue(t, site.Domains, func(c *x509.Certificate) { c.NotAfter = time.Now().Add(-time.Minute) })
	future, futureKey := issuer.Issue(t, site.Domains, func(c *x509.Certificate) { c.NotBefore = time.Now().Add(time.Hour) })
	tests := []struct {
		name string
		cert []byte
		key  []byte
	}{
		{"mismatched key", cert, wrongKey},
		{"untrusted chain", untrustedCert, untrustedKey},
		{"wrong hostname", wrongName, wrongNameKey},
		{"expired", expired, expiredKey},
		{"not yet valid", future, futureKey},
		{"trailing junk", append(append([]byte{}, cert...), []byte("garbage")...), key},
		{"prefixed junk", append([]byte("ignored preamble\n"), cert...), key},
		{"multiple keys", cert, append(append([]byte{}, key...), key...)},
		{"oversized", bytes.Repeat([]byte("x"), MaxPEMBytes+1), key},
		{"root first", append(append([]byte{}, pki.PEM...), cert...), key},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Parse(tt.cert, tt.key, site, time.Now(), time.Hour); err == nil {
				t.Fatal("invalid bundle accepted")
			}
		})
	}
}

func TestWildcardCoversConcreteConfiguredNames(t *testing.T) {
	pki := testutil.NewPKI(t, t.TempDir())
	cert, key := pki.Issue(t, []string{"*.example.test"}, nil)
	site := config.Site{Domains: []string{"a.example.test", "b.example.test"}, CAFile: pki.CAFile}
	if _, err := Parse(cert, key, site, time.Now(), time.Hour); err != nil {
		t.Fatal(err)
	}
	site.Domains = append(site.Domains, "deep.a.example.test")
	if _, err := Parse(cert, key, site, time.Now(), time.Hour); err == nil {
		t.Fatal("wildcard incorrectly covered nested label")
	}
}
