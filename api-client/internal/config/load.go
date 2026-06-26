package config

import (
	"fmt"
	"os"
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
	cfg.RenewBefore = 720 * time.Hour
	if cfg.RenewRaw != "" {
		d, err := time.ParseDuration(cfg.RenewRaw)
		if err != nil {
			return fmt.Errorf("invalid renew_before: %w", err)
		}
		cfg.RenewBefore = d
	}
	if cfg.JitterRaw != "" {
		d, err := time.ParseDuration(cfg.JitterRaw)
		if err != nil {
			return fmt.Errorf("invalid jitter: %w", err)
		}
		cfg.Jitter = d
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

func validate(cfg *Config) error {
	if cfg.Server.URL == "" {
		return fmt.Errorf("server.url is required")
	}
	if cfg.Server.ClientID == "" || cfg.Server.Secret == "" {
		return fmt.Errorf("server.client_id and server.secret are required")
	}
	if len(cfg.Domains) == 0 {
		return fmt.Errorf("at least one domain is required")
	}
	for i, d := range cfg.Domains {
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
