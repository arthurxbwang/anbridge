package certificate

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	"anbridge/internal/config"
)

const MaxPEMBytes = 128 * 1024

type Bundle struct {
	CertPEM          []byte
	KeyPEM           []byte
	Fingerprint      string
	ChainFingerprint string
	Version          string
	NotAfter         time.Time
}

func RootPool(caFile string) (*x509.CertPool, error) {
	if caFile == "" {
		return x509.SystemCertPool()
	}
	data, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, errors.New("configured CA file contains no certificates")
	}
	return pool, nil
}

func Parse(certPEM, keyPEM []byte, site config.Site, now time.Time, minValidity time.Duration) (*Bundle, error) {
	if len(certPEM) == 0 || len(keyPEM) == 0 || len(certPEM) > MaxPEMBytes || len(keyPEM) > MaxPEMBytes {
		return nil, errors.New("empty or oversized certificate/key")
	}
	var certs []*x509.Certificate
	var normalized []byte
	rest := bytes.TrimSpace(certPEM)
	for len(rest) != 0 {
		if !bytes.HasPrefix(rest, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, errors.New("certificate chain contains unexpected data")
		}
		block, remaining := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, errors.New("invalid certificate PEM")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errors.New("invalid certificate DER")
		}
		certs = append(certs, cert)
		if len(certs) > 12 {
			return nil, errors.New("certificate chain is too long")
		}
		normalized = append(normalized, pem.EncodeToMemory(block)...)
		rest = bytes.TrimSpace(remaining)
	}
	if len(certs) == 0 || certs[0].IsCA {
		return nil, errors.New("first certificate must be a server leaf certificate")
	}
	keyPEM = bytes.TrimSpace(keyPEM)
	if !bytes.HasPrefix(keyPEM, []byte("-----BEGIN ")) {
		return nil, errors.New("invalid private key PEM")
	}
	keyBlock, remaining := pem.Decode(keyPEM)
	if keyBlock == nil || len(bytes.TrimSpace(remaining)) != 0 || len(keyBlock.Headers) != 0 {
		return nil, errors.New("expected a single unencrypted private key")
	}
	switch keyBlock.Type {
	case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY":
	default:
		return nil, errors.New("unsupported private key PEM type")
	}
	normalizedKey := pem.EncodeToMemory(keyBlock)
	if _, err := tls.X509KeyPair(normalized, normalizedKey); err != nil {
		return nil, errors.New("certificate and private key do not form a valid pair")
	}
	leaf := certs[0]
	if leaf.NotBefore.After(now) || leaf.NotAfter.Before(now.Add(minValidity)) {
		return nil, errors.New("certificate is not yet valid or has insufficient remaining lifetime")
	}
	for _, name := range site.Domains {
		if err := leaf.VerifyHostname(name); err != nil {
			return nil, fmt.Errorf("certificate does not cover configured domain %s", name)
		}
	}
	for i := 0; i+1 < len(certs); i++ {
		if err := certs[i].CheckSignatureFrom(certs[i+1]); err != nil {
			return nil, errors.New("certificate chain is not in leaf-to-issuer order")
		}
	}
	roots, err := RootPool(site.CAFile)
	if err != nil {
		return nil, fmt.Errorf("load trust roots: %w", err)
	}
	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: intermediates, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return nil, fmt.Errorf("certificate chain verification failed: %w", err)
	}
	fingerprint := sha256.Sum256(leaf.Raw)
	h := sha256.New()
	h.Write(normalized)
	h.Write([]byte{0})
	h.Write(normalizedKey)
	return &Bundle{
		CertPEM: normalized, KeyPEM: normalizedKey,
		Fingerprint:      hex.EncodeToString(fingerprint[:]),
		ChainFingerprint: ChainFingerprint(certs),
		Version:          hex.EncodeToString(h.Sum(nil)), NotAfter: leaf.NotAfter.UTC(),
	}, nil
}

// ChainFingerprint identifies the presented leaf/intermediate chain. A
// self-signed trust anchor may legitimately be omitted by the TLS server.
func ChainFingerprint(certs []*x509.Certificate) string {
	h := sha256.New()
	for _, cert := range certs {
		if cert.IsCA && bytes.Equal(cert.RawSubject, cert.RawIssuer) && cert.CheckSignatureFrom(cert) == nil {
			continue
		}
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(cert.Raw)))
		h.Write(size[:])
		h.Write(cert.Raw)
	}
	return hex.EncodeToString(h.Sum(nil))
}
