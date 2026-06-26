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
	base     string
	clientID string
	secret   string
	http     *http.Client

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
		base:     strings.TrimRight(baseURL, "/"),
		clientID: clientID,
		secret:   secret,
		http:     &http.Client{Timeout: 30 * time.Second, Transport: tr},
	}
}

func (c *Client) authToken(ctx context.Context, force bool) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !force && c.token != "" && time.Now().Before(c.expires) {
		return c.token, nil
	}
	body, _ := json.Marshal(map[string]string{"client_id": c.clientID, "secret": c.secret})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/api/auth/token", bytes.NewReader(body))
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

// do performs an authenticated GET, retrying once with a fresh token on 401.
func (c *Client) do(ctx context.Context, path string) ([]byte, error) {
	for attempt := 0; attempt < 2; attempt++ {
		tok, err := c.authToken(ctx, attempt == 1)
		if err != nil {
			return nil, err
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := c.http.Do(req)
		if err != nil {
			return nil, fmt.Errorf("request %s: %w", path, err)
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			continue
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("GET %s: status %d", path, resp.StatusCode)
		}
		return raw, nil
	}
	return nil, fmt.Errorf("GET %s: unauthorized after re-auth", path)
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
