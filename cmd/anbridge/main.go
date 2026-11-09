package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"anbridge/internal/api"
	"anbridge/internal/atomicfile"
	"anbridge/internal/config"
	"anbridge/internal/deploy"
	"anbridge/internal/helper"
	"anbridge/internal/nginx"
)

var version = "0.1.0-dev"

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(os.Args[1:], logger); err != nil {
		logger.Error("anbridge stopped", "error", err)
		os.Exit(1)
	}
}

func run(args []string, logger *slog.Logger) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: anbridge <serve|deployd|bootstrap|check-config|version> [flags]")
	}
	if args[0] == "version" {
		fmt.Println(version)
		return nil
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	configPath := flags.String("config", "/etc/anbridge/config.json", "configuration JSON")
	var siteID, certPath, keyPath *string
	if args[0] == "bootstrap" {
		siteID = flags.String("site", "", "configured site ID")
		certPath = flags.String("cert", "", "existing working full-chain PEM")
		keyPath = flags.String("key", "", "existing matching private-key PEM")
	}
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if len(flags.Args()) != 0 {
		return fmt.Errorf("unexpected positional arguments")
	}
	switch args[0] {
	case "serve", "deployd", "bootstrap", "check-config":
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if args[0] == "check-config" {
		fmt.Printf("configuration valid: %d site(s)\n", len(cfg.Sites))
		return nil
	}
	if args[0] == "serve" {
		if os.Geteuid() == 0 {
			return fmt.Errorf("HTTPS receiver must run as an unprivileged user; use the provided systemd service")
		}
		handler, err := api.New(cfg, helper.NewClient(cfg), logger)
		if err != nil {
			return err
		}
		server := &http.Server{
			Addr: cfg.Listen, Handler: handler,
			TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
			ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second,
			WriteTimeout: 2*cfg.OperationTimeout() + 5*time.Second,
			IdleTimeout:  30 * time.Second, MaxHeaderBytes: 16 * 1024,
		}
		return serve(server, func() error { return server.ListenAndServeTLS(cfg.TLS.CertFile, cfg.TLS.KeyFile) }, logger, "receiver", 2*cfg.OperationTimeout()+5*time.Second)
	}
	if os.Geteuid() == 0 {
		if err := cfg.CheckPrivilegedPaths(*configPath); err != nil {
			return err
		}
	}
	driver := &nginx.Local{Config: cfg.Nginx, ProbeTimeout: time.Duration(cfg.ProbeTimeoutSeconds) * time.Second}
	engine, err := deploy.Open(cfg, driver, logger)
	if err != nil {
		return err
	}
	defer engine.Close()
	if args[0] == "bootstrap" {
		if *siteID == "" || *certPath == "" || *keyPath == "" {
			return fmt.Errorf("bootstrap requires -site, -cert, and -key")
		}
		cert, err := atomicfile.ReadRegular(*certPath, 128*1024)
		if err != nil {
			return err
		}
		key, err := atomicfile.ReadRegular(*keyPath, 128*1024)
		if err != nil {
			return err
		}
		active, err := engine.Bootstrap(*siteID, cert, key)
		if err != nil {
			return err
		}
		site, _ := cfg.Site(*siteID)
		fmt.Printf("baseline created: %s\nAdd this inside the intended nginx server block:\n  include %s;\nThen validate/reload nginx and verify the baseline before starting deployd.\n", active.Fingerprint, site.IncludeFile)
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), cfg.OperationTimeout())
	err = engine.Recover(ctx)
	cancel()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(cfg.SocketPath), 0750); err != nil {
		return err
	}
	listener, err := helper.Listen(cfg.SocketPath, cfg.SocketGroup)
	if err != nil {
		return err
	}
	defer listener.Close()
	server := &http.Server{
		Handler: helper.Handler(engine), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 20 * time.Second, WriteTimeout: 2*cfg.OperationTimeout() + 5*time.Second,
		IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8 * 1024,
	}
	return serve(server, func() error { return server.Serve(listener) }, logger, "deploy-helper", 2*cfg.OperationTimeout()+5*time.Second)
}

func serve(server *http.Server, start func() error, logger *slog.Logger, role string, stopTimeout time.Duration) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	result := make(chan error, 1)
	go func() { result <- start() }()
	logger.Info("service starting", "role", role, "version", version)
	select {
	case err := <-result:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	case <-ctx.Done():
		// Finish in-flight transactions before exiting; systemd allows this budget.
		shutdown, cancel := context.WithTimeout(context.Background(), stopTimeout)
		defer cancel()
		return server.Shutdown(shutdown)
	}
}
