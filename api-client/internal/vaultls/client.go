package vaultls

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Cert struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	CreatedOn  int64  `json:"created_on"`
	ValidUntil int64  `json:"valid_until"`
	RevokedAt  *int64 `json:"revoked_at"`
}

type Client struct {
	base      string
	clientID  string
	secret    string
	http      *http.Client
	retryBase time.Duration

	mu      sync.Mutex
	token   string
	expires time.Time
}

func New(baseURL, clientID, secret string, insecure bool) *Client {
	tr := &http.Transport{}
	if insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &Client{
		base:      strings.TrimRight(baseURL, "/"),
		clientID:  clientID,
		secret:    secret,
		http:      &http.Client{Timeout: 30 * time.Second, Transport: tr},
		retryBase: 1 * time.Second,
	}
}

func (c *Client) authToken(ctx context.Context, force bool) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !force && c.token != "" && time.Now().Before(c.expires) {
		return c.token, nil
	}
	body, _ := json.Marshal(map[string]string{"client_id": c.clientID, "secret": c.secret})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/api/auth/token", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("auth: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("auth request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("auth failed: status %d", resp.StatusCode)
	}
	var tr struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return "", fmt.Errorf("auth decode: %w", err)
	}
	c.token = tr.AccessToken
	c.expires = time.Now().Add(time.Duration(tr.ExpiresIn)*time.Second - 30*time.Second)
	return c.token, nil
}

// do performs an authenticated GET. It retries up to 3 times on transient
// failures (network errors or status >= 500) with exponential backoff, and
// composes a single forced re-auth on a 401 (which is not a transient retry).
func (c *Client) do(ctx context.Context, path string) ([]byte, error) {
	const maxAttempts = 3
	reauthed := false
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			delay := c.retryBase << (attempt - 1)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
		}

		tok, err := c.authToken(ctx, false)
		if err != nil {
			return nil, err
		}
		raw, status, transient, err := c.get(ctx, path, tok)
		if err != nil {
			if transient {
				lastErr = err
				continue
			}
			return nil, err
		}

		// One forced re-auth on 401; not counted as a transient retry.
		if status == http.StatusUnauthorized && !reauthed {
			reauthed = true
			tok, err = c.authToken(ctx, true)
			if err != nil {
				return nil, err
			}
			raw, status, transient, err = c.get(ctx, path, tok)
			if err != nil {
				if transient {
					lastErr = err
					continue
				}
				return nil, err
			}
		}

		if status >= 500 {
			lastErr = fmt.Errorf("GET %s: status %d", path, status)
			continue
		}
		if status != http.StatusOK {
			return nil, fmt.Errorf("GET %s: status %d", path, status)
		}
		return raw, nil
	}
	return nil, lastErr
}

// get performs a single authenticated GET. transient reports whether a non-nil
// err is a retryable network failure (vs. a fatal request-build error).
func (c *Client) get(ctx context.Context, path, tok string) (raw []byte, status int, transient bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return nil, 0, false, fmt.Errorf("build request %s: %w", path, err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, true, fmt.Errorf("request %s: %w", path, err)
	}
	raw, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	return raw, resp.StatusCode, false, nil
}

func (c *Client) List(ctx context.Context) ([]Cert, error) {
	raw, err := c.do(ctx, "/api/certificates")
	if err != nil {
		return nil, err
	}
	var certs []Cert
	if err := json.Unmarshal(raw, &certs); err != nil {
		return nil, fmt.Errorf("decode certificates: %w", err)
	}
	return certs, nil
}

func (c *Client) Password(ctx context.Context, id int64) (string, error) {
	raw, err := c.do(ctx, fmt.Sprintf("/api/certificates/%d/password", id))
	if err != nil {
		return "", err
	}
	var pw string
	if err := json.Unmarshal(raw, &pw); err != nil {
		return "", fmt.Errorf("decode password: %w", err)
	}
	return pw, nil
}

func (c *Client) Download(ctx context.Context, id int64) ([]byte, error) {
	return c.do(ctx, fmt.Sprintf("/api/certificates/%d/download", id))
}

// SelectForName returns the non-revoked cert with the given name and the
// greatest ValidUntil.
func SelectForName(certs []Cert, name string) (Cert, bool) {
	var best Cert
	found := false
	for _, c := range certs {
		if c.Name != name || c.RevokedAt != nil {
			continue
		}
		if !found || c.ValidUntil > best.ValidUntil {
			best = c
			found = true
		}
	}
	return best, found
}
