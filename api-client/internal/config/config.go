package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Server struct {
	URL                string `yaml:"url"`
	ClientID           string `yaml:"client_id"`
	Secret             string `yaml:"secret"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
}

type Domain struct {
	Name    string   `yaml:"name"`
	OutDir  string   `yaml:"out_dir"`
	Formats []string `yaml:"formats"`
	Owner   string   `yaml:"owner"`
	Group   string   `yaml:"group"`
	Mode    string   `yaml:"mode"`
	Reload  string   `yaml:"reload"`
	CertID  int64    `yaml:"cert_id"`
}

type Config struct {
	Server      Server        `yaml:"server"`
	Schedule    string        `yaml:"schedule"`
	Jitter      time.Duration `yaml:"-"`
	JitterRaw   string        `yaml:"jitter"`
	RenewBefore time.Duration `yaml:"-"`
	RenewRaw    string        `yaml:"renew_before"`
	Exporter    struct {
		Listen string `yaml:"listen"`
	} `yaml:"exporter"`
	Domains []Domain `yaml:"domains"`
}

// FileMode parses the octal Mode string, defaulting to 0640.
func (d Domain) FileMode() (os.FileMode, error) {
	s := d.Mode
	if s == "" {
		s = "0640"
	}
	v, err := strconv.ParseUint(strings.TrimPrefix(s, "0o"), 8, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid mode %q: %w", d.Mode, err)
	}
	return os.FileMode(v), nil
}
