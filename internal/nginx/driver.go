package nginx

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"

	"anbridge/internal/certificate"
	"anbridge/internal/config"
)

type Driver interface {
	Test(context.Context) error
	Reload(context.Context) error
	Verify(context.Context, config.Site, string, string) error
}

type Local struct {
	Config       config.Nginx
	ProbeTimeout time.Duration
}

type limitedBuffer struct {
	data []byte
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if remaining := 8192 - len(b.data); remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		b.data = append(b.data, p...)
	}
	return n, nil
}

func (d *Local) command(ctx context.Context, operation string) error {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(d.Config.CommandTimeoutSeconds)*time.Second)
	defer cancel()
	args := []string{"-p", d.Config.Prefix, "-c", d.Config.Config}
	switch operation {
	case "test":
		args = append(args, "-t")
	case "reload":
		args = append(args, "-s", "reload")
	default:
		return errors.New("unsupported nginx operation")
	}
	cmd := exec.CommandContext(ctx, d.Config.Binary, args...)
	// Do not forward service secrets or loader injection variables to nginx.
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
	var output limitedBuffer
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nginx %s failed: %w: %s", operation, err, strings.TrimSpace(string(output.data)))
	}
	return nil
}

func (d *Local) Test(ctx context.Context) error   { return d.command(ctx, "test") }
func (d *Local) Reload(ctx context.Context) error { return d.command(ctx, "reload") }

func (d *Local) Verify(ctx context.Context, site config.Site, fingerprint, chainFingerprint string) error {
	ctx, cancel := context.WithTimeout(ctx, d.ProbeTimeout)
	defer cancel()
	roots, err := certificate.RootPool(site.CAFile)
	if err != nil {
		return err
	}
	for {
		var lastErr error
		for _, p := range site.Probes {
			dialer := tls.Dialer{
				NetDialer: &net.Dialer{Timeout: 2 * time.Second},
				Config: &tls.Config{
					MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: p.ServerName,
					// A nil session cache ensures every probe authenticates the served chain.
					ClientSessionCache: nil,
				},
			}
			conn, err := dialer.DialContext(ctx, "tcp", p.Address)
			if err != nil {
				lastErr = fmt.Errorf("TLS probe for %s failed: %w", p.ServerName, err)
				break
			}
			state := conn.(*tls.Conn).ConnectionState()
			_ = conn.Close()
			if len(state.PeerCertificates) == 0 {
				lastErr = errors.New("TLS probe returned no peer certificate")
				break
			}
			hash := sha256.Sum256(state.PeerCertificates[0].Raw)
			if hex.EncodeToString(hash[:]) != fingerprint {
				lastErr = fmt.Errorf("TLS probe for %s returned a different certificate", p.ServerName)
				break
			}
			if certificate.ChainFingerprint(state.PeerCertificates) != chainFingerprint {
				lastErr = fmt.Errorf("TLS probe for %s returned a different intermediate chain", p.ServerName)
				break
			}
		}
		if lastErr == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return lastErr
		case <-time.After(150 * time.Millisecond):
		}
	}
}
