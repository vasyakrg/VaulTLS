package config

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	expanded := os.Expand(string(raw), func(k string) string { return os.Getenv(k) })

	var cfg Config
	if err := yaml.Unmarshal([]byte(expanded), &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := applyDefaults(&cfg); err != nil {
		return nil, err
	}
	if err := validate(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func applyDefaults(cfg *Config) error {
	if cfg.Schedule == "" {
		cfg.Schedule = "0 3 1 * *"
	}
	if cfg.Exporter.Listen == "" {
		cfg.Exporter.Listen = "127.0.0.1:9105"
	}
	if cfg.JitterRaw != "" {
		d, err := time.ParseDuration(cfg.JitterRaw)
		if err != nil {
			return fmt.Errorf("invalid jitter: %w", err)
		}
		cfg.Jitter = d
	}
	if cfg.CATrust.Enabled {
		if err := applyCATrustDefaults(&cfg.CATrust, dirExists); err != nil {
			return err
		}
	}
	for i := range cfg.Domains {
		d := &cfg.Domains[i]
		if len(d.Formats) == 0 {
			d.Formats = []string{"pem"}
		}
		if d.OutDir == "" && d.Name != "" {
			d.OutDir = "/etc/ssl/vaultls/" + strings.TrimPrefix(d.Name, "*.")
		}
	}
	return nil
}

// caTrustPlatforms lists the system trust stores the agent knows, in probe
// order. The package only ships as a .deb, but the binary builds anywhere, so
// RHEL-style hosts are detected instead of requiring a manual override.
var caTrustPlatforms = []struct{ dir, command string }{
	{"/usr/local/share/ca-certificates", "update-ca-certificates"},
	{"/etc/pki/ca-trust/source/anchors", "update-ca-trust extract"},
}

func dirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

// applyCATrustDefaults fills anchor_dir/update_command from the detected
// platform. exists is injected so tests do not depend on the host's layout.
func applyCATrustDefaults(c *CATrust, exists func(string) bool) error {
	if c.AnchorDir == "" {
		for _, p := range caTrustPlatforms {
			if exists(p.dir) {
				c.AnchorDir = p.dir
				break
			}
		}
	}
	if c.AnchorDir == "" {
		return fmt.Errorf("ca_trust.enabled is set but no known system trust store was found: " +
			"set ca_trust.anchor_dir and ca_trust.update_command explicitly")
	}
	if c.UpdateCommand == "" {
		for _, p := range caTrustPlatforms {
			if p.dir == c.AnchorDir {
				c.UpdateCommand = p.command
				break
			}
		}
	}
	if c.UpdateCommand == "" {
		return fmt.Errorf("ca_trust.update_command is required for anchor_dir %q", c.AnchorDir)
	}
	return nil
}

func validate(cfg *Config) error {
	if cfg.Server.URL == "" {
		return fmt.Errorf("server.url is required")
	}
	if u, err := url.Parse(cfg.Server.URL); err != nil ||
		(u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("server.url is not a valid http(s) URL")
	}
	if cfg.Server.ClientID == "" || cfg.Server.Secret == "" {
		return fmt.Errorf("server.client_id and server.secret are required")
	}
	if cfg.CATrust.Enabled && !filepath.IsAbs(cfg.CATrust.AnchorDir) {
		return fmt.Errorf("ca_trust.anchor_dir must be an absolute path, got %q", cfg.CATrust.AnchorDir)
	}
	if len(cfg.Domains) == 0 {
		return fmt.Errorf("at least one domain is required")
	}
	// Two entries writing into one directory would silently overwrite each
	// other's key material on every reconcile.
	seenOutDir := map[string]int{}
	for i, d := range cfg.Domains {
		if d.OutDir != "" {
			if first, dup := seenOutDir[d.OutDir]; dup {
				return fmt.Errorf("domain[%d] (%s): out_dir %q already used by domain[%d]", i, d.Name, d.OutDir, first)
			}
			seenOutDir[d.OutDir] = i
		}
		if d.Name == "" && d.CertID == 0 {
			return fmt.Errorf("domain[%d]: name or cert_id required", i)
		}
		if d.Name == "" && d.OutDir == "" {
			return fmt.Errorf("domain[%d]: out_dir is required when name is empty", i)
		}
		if d.Reload == "" {
			return fmt.Errorf("domain[%d] (%s): reload is required", i, d.Name)
		}
		for _, f := range d.Formats {
			if f != "pem" && f != "haproxy" {
				return fmt.Errorf("domain[%d] (%s): unknown format %q", i, d.Name, f)
			}
		}
		if _, err := d.FileMode(); err != nil {
			return fmt.Errorf("domain[%d] (%s): %w", i, d.Name, err)
		}
	}
	return nil
}
