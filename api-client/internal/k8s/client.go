// Package k8s is a minimal Kubernetes REST client covering exactly what the
// agent needs: read, create and merge-patch one Secret per configured domain.
// client-go would pull ~40 MB of dependencies into a binary that also ships as
// a .deb to plain nodes, for three verbs on one resource type.
package k8s

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// ErrNotFound is returned by GetSecret when the object does not exist.
var ErrNotFound = errors.New("not found")

const saDir = "/var/run/secrets/kubernetes.io/serviceaccount"

type ObjectMeta struct {
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

// Secret mirrors the fields of v1.Secret the agent reads or writes. Data is
// []byte so encoding/json handles the base64 the API expects.
type Secret struct {
	APIVersion string            `json:"apiVersion,omitempty"`
	Kind       string            `json:"kind,omitempty"`
	Metadata   ObjectMeta        `json:"metadata"`
	Type       string            `json:"type,omitempty"`
	Data       map[string][]byte `json:"data,omitempty"`
}

// Client talks to the API server with the pod's service account credentials.
type Client struct {
	base  string
	http  *http.Client
	token func() (string, error)
}

// InCluster builds a client from the projected service account volume. The
// token is re-read per request: projected tokens are rotated by the kubelet,
// and a cached one goes stale after roughly an hour.
func InCluster() (*Client, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, fmt.Errorf("not running in a cluster: KUBERNETES_SERVICE_HOST/PORT are unset")
	}
	caPEM, err := os.ReadFile(saDir + "/ca.crt")
	if err != nil {
		return nil, fmt.Errorf("read cluster CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("cluster CA at %s/ca.crt contains no certificates", saDir)
	}
	tokenPath := saDir + "/token"
	if _, err := os.ReadFile(tokenPath); err != nil {
		return nil, fmt.Errorf("read service account token: %w", err)
	}
	return &Client{
		base: fmt.Sprintf("https://%s", hostPort(host, port)),
		http: &http.Client{
			Timeout:   30 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
		},
		token: func() (string, error) {
			raw, err := os.ReadFile(tokenPath)
			if err != nil {
				return "", fmt.Errorf("read service account token: %w", err)
			}
			return strings.TrimSpace(string(raw)), nil
		},
	}, nil
}

// hostPort joins host and port, bracketing IPv6 literals.
func hostPort(host, port string) string {
	if strings.Contains(host, ":") {
		return "[" + host + "]:" + port
	}
	return host + ":" + port
}

// NewForTest builds a client against an arbitrary base URL with a static token.
func NewForTest(base, token string, hc *http.Client) *Client {
	if hc == nil {
		hc = &http.Client{Timeout: 5 * time.Second}
	}
	return &Client{base: base, http: hc, token: func() (string, error) { return token, nil }}
}

// InClusterNamespace reads the namespace the pod runs in.
func InClusterNamespace() (string, error) {
	raw, err := os.ReadFile(saDir + "/namespace")
	if err != nil {
		return "", fmt.Errorf("read pod namespace: %w", err)
	}
	return strings.TrimSpace(string(raw)), nil
}

func (c *Client) secretPath(ns, name string) string {
	p := c.base + "/api/v1/namespaces/" + ns + "/secrets"
	if name != "" {
		p += "/" + name
	}
	return p
}

func (c *Client) do(ctx context.Context, method, url, contentType string, body []byte) ([]byte, error) {
	tok, err := c.token()
	if err != nil {
		return nil, err
	}
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNotFound
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("%s %s: %s: %s", method, redactPath(url), resp.Status, apiMessage(raw))
	}
	return raw, nil
}

// redactPath strips the scheme and host so logs carry the resource path only.
func redactPath(u string) string {
	if i := strings.Index(u, "/api/"); i >= 0 {
		return u[i:]
	}
	return u
}

// apiMessage lifts the human-readable message out of a v1.Status body.
func apiMessage(raw []byte) string {
	var st struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(raw, &st); err == nil && st.Message != "" {
		return st.Message
	}
	return strings.TrimSpace(string(raw))
}

// GetSecret returns the Secret, or ErrNotFound.
func (c *Client) GetSecret(ctx context.Context, ns, name string) (*Secret, error) {
	raw, err := c.do(ctx, http.MethodGet, c.secretPath(ns, name), "", nil)
	if err != nil {
		return nil, err
	}
	var s Secret
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("decode secret: %w", err)
	}
	return &s, nil
}

// CreateSecret creates the Secret.
func (c *Client) CreateSecret(ctx context.Context, s *Secret) error {
	s.APIVersion, s.Kind = "v1", "Secret"
	body, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("encode secret: %w", err)
	}
	_, err = c.do(ctx, http.MethodPost, c.secretPath(s.Metadata.Namespace, ""), "application/json", body)
	return err
}

// PatchSecret applies a JSON merge patch. Only the keys present in the patch
// are touched, so labels and annotations added by other controllers survive.
func (c *Client) PatchSecret(ctx context.Context, ns, name string, patch []byte) error {
	_, err := c.do(ctx, http.MethodPatch, c.secretPath(ns, name), "application/merge-patch+json", patch)
	return err
}
