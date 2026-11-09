ROOT := $(abspath .)
LOCAL_GO := $(ROOT)/.tools/sysroot/usr/lib/go-1.27/bin/go
GO ?= $(if $(wildcard $(LOCAL_GO)),$(LOCAL_GO),go)
export GOTOOLCHAIN := local
export GOCACHE := $(ROOT)/.cache/go-build
export GOMODCACHE := $(ROOT)/.cache/go-mod
export TMPDIR := $(ROOT)/.tmp
NGINX_BIN ?= $(ROOT)/.tools/sysroot/usr/sbin/nginx
export NGINX_BIN

.PHONY: prepare fmt check test integration build units
prepare:
	@mkdir -p "$(TMPDIR)" "$(GOCACHE)" "$(GOMODCACHE)" bin
fmt: prepare
	$(GO) fmt ./...
check: prepare
	$(GO) vet ./...
test: prepare
	$(GO) test -race -count=1 ./...
integration: prepare
	@test -x "$(NGINX_BIN)" || (echo 'Set NGINX_BIN to a real nginx binary'; exit 1)
	ANBRIDGE_INTEGRATION=1 $(GO) test -race -count=1 -v ./integration
build: prepare
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="-s -w" -o bin/anbridge ./cmd/anbridge
units: build
	python3 scripts/check-units.py
