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
	Name     string   `yaml:"name"`
	OutDir   string   `yaml:"out_dir"`
	Basename string   `yaml:"basename"`
	Formats  []string `yaml:"formats"`
	Owner    string   `yaml:"owner"`
	Group    string   `yaml:"group"`
	Mode     string   `yaml:"mode"`
	Reload   string   `yaml:"reload"`
	CertID   int64    `yaml:"cert_id"`
}

// FileNames are the on-disk names writeBundle uses for one domain.
type FileNames struct {
	Fullchain string
	Cert      string
	Chain     string
	PrivKey   string
	Haproxy   string
}

// defaultFileNames is the historic layout, kept for every domain that does not
// set basename: renaming files under an existing deployment would break the
// paths already referenced by nginx/haproxy configs.
var defaultFileNames = FileNames{
	Fullchain: "fullchain.pem",
	Cert:      "cert.pem",
	Chain:     "chain.pem",
	PrivKey:   "privkey.pem",
	Haproxy:   "haproxy.pem",
}

// FileNames derives the output file names from basename. The fullchain — the
// file most configs point at — takes the bare name, the rest are suffixed.
func (d Domain) FileNames() FileNames {
	if d.Basename == "" {
		return defaultFileNames
	}
	return FileNames{
		Fullchain: d.Basename + ".pem",
		Cert:      d.Basename + "-cert.pem",
		Chain:     d.Basename + "-chain.pem",
		PrivKey:   d.Basename + "-key.pem",
		Haproxy:   d.Basename + "-haproxy.pem",
	}
}

// Log configures the agent's structured logging. Zero values keep the historic
// behaviour: INFO level, text format, written to stderr (captured by journald).
type Log struct {
	Level  string `yaml:"level"`  // debug|info|warn|error (default info)
	Format string `yaml:"format"` // text|json (default text)
	File   string `yaml:"file"`   // optional path; when set, logs go here instead of stderr
}

// CATrust configures publishing the VaulTLS root CAs into the host's system
// trust store. Disabled by default: the agent must never change host-wide trust
// without an explicit opt-in.
type CATrust struct {
	Enabled       bool   `yaml:"enabled"`
	AnchorDir     string `yaml:"anchor_dir"`
	UpdateCommand string `yaml:"update_command"`
}

// FileExt is the anchor file extension implied by AnchorDir. Debian's
// update-ca-certificates only picks up .crt, RHEL's ca-trust anchors are .pem;
// deriving it from the directory keeps an anchor_dir override self-sufficient.
func (c CATrust) FileExt() string {
	if strings.HasPrefix(c.AnchorDir, "/etc/pki/") {
		return ".pem"
	}
	return ".crt"
}

type Config struct {
	Server    Server        `yaml:"server"`
	Schedule  string        `yaml:"schedule"`
	Jitter    time.Duration `yaml:"-"`
	JitterRaw string        `yaml:"jitter"`
	Log       Log           `yaml:"log"`
	CATrust   CATrust       `yaml:"ca_trust"`
	Exporter  struct {
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
