// Package helper exposes only typed operations over a local Unix socket.
package helper

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"strconv"
	"time"

	"anbridge/internal/config"
	"anbridge/internal/deploy"
)

type Backend interface {
	Activate(deploy.Request) (deploy.Result, error)
	Status(string) (deploy.Status, error)
}

type reply struct {
	Error  string         `json:"error,omitempty"`
	Result *deploy.Result `json:"result,omitempty"`
	Status *deploy.Status `json:"status,omitempty"`
}

func Handler(engine Backend) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v1/deploy" && r.Method == http.MethodPost:
			var req deploy.Request
			d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 384*1024))
			d.DisallowUnknownFields()
			if err := d.Decode(&req); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(reply{Error: "invalid deploy request"})
				return
			}
			var extra any
			if err := d.Decode(&extra); err != io.EOF {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(reply{Error: "invalid trailing data"})
				return
			}
			result, err := engine.Activate(req)
			if err != nil {
				code := http.StatusBadRequest
				if errors.Is(err, deploy.ErrBusy) {
					code = http.StatusConflict
				}
				w.WriteHeader(code)
				_ = json.NewEncoder(w).Encode(reply{Error: err.Error()})
				return
			}
			_ = json.NewEncoder(w).Encode(reply{Result: &result})
		case r.URL.Path == "/v1/status" && r.Method == http.MethodGet:
			status, err := engine.Status(r.URL.Query().Get("site"))
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(reply{Error: err.Error()})
				return
			}
			_ = json.NewEncoder(w).Encode(reply{Status: &status})
		default:
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(reply{Error: "not found"})
		}
	})
}

func Listen(path, group string) (net.Listener, error) {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("helper socket path exists and is not a Unix socket")
		}
		// A live listener must never be unlinked.
		conn, err := net.DialTimeout("unix", path, time.Second)
		if err == nil {
			conn.Close()
			return nil, errors.New("helper socket is already in use")
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0600); err != nil {
		l.Close()
		return nil, err
	}
	if group != "" {
		g, err := user.LookupGroup(group)
		if err != nil {
			l.Close()
			return nil, err
		}
		gid, err := strconv.Atoi(g.Gid)
		if err != nil {
			l.Close()
			return nil, err
		}
		if err := os.Chown(path, -1, gid); err != nil {
			l.Close()
			return nil, err
		}
		if err := os.Chmod(path, 0660); err != nil {
			l.Close()
			return nil, err
		}
	}
	return l, nil
}

type Client struct {
	http *http.Client
}

func NewClient(cfg *config.Config) *Client {
	return &Client{http: &http.Client{
		Timeout: 2 * cfg.OperationTimeout(),
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", cfg.SocketPath)
			},
			MaxConnsPerHost: 4,
		},
	}}
}

func (c *Client) call(method, path string, body io.Reader) (reply, error) {
	req, err := http.NewRequest(method, "http://unix"+path, body)
	if err != nil {
		return reply{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(req)
	if err != nil {
		return reply{}, err
	}
	defer response.Body.Close()
	var result reply
	if err := json.NewDecoder(io.LimitReader(response.Body, 64*1024)).Decode(&result); err != nil {
		return result, err
	}
	if result.Error != "" {
		if response.StatusCode == http.StatusConflict {
			return result, deploy.ErrBusy
		}
		return result, errors.New(result.Error)
	}
	if response.StatusCode != http.StatusOK {
		return result, fmt.Errorf("helper HTTP status %d", response.StatusCode)
	}
	return result, nil
}

func (c *Client) Status(site string) (deploy.Status, error) {
	result, err := c.call(http.MethodGet, "/v1/status?site="+url.QueryEscape(site), nil)
	if err != nil {
		return deploy.Status{}, err
	}
	if result.Status == nil {
		return deploy.Status{}, errors.New("helper returned no status")
	}
	return *result.Status, nil
}

func (c *Client) Activate(req deploy.Request) (deploy.Result, error) {
	// bytes.Reader is intentional: private material never passes through a shell.
	data, err := json.Marshal(req)
	if err != nil {
		return deploy.Result{}, err
	}
	result, err := c.call(http.MethodPost, "/v1/deploy", bytes.NewReader(data))
	if err != nil {
		return deploy.Result{}, err
	}
	if result.Result == nil {
		return deploy.Result{}, errors.New("helper returned no deployment result")
	}
	return *result.Result, nil
}
