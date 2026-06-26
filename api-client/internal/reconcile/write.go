package reconcile

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"

	"github.com/vasyakrg/vaultls-agent/internal/config"
	"github.com/vasyakrg/vaultls-agent/internal/pki"
)

// writeFile atomically writes data to dir/name with the given mode, then
// best-effort applies owner/group from the domain.
func writeFile(dir, name string, data []byte, mode os.FileMode, d config.Domain) error {
	final := filepath.Join(dir, name)
	tmp := final + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return fmt.Errorf("chmod %s: %w", name, err)
	}
	if uid, gid, ok := lookupOwner(d); ok {
		_ = os.Chown(tmp, uid, gid)
	}
	if err := os.Rename(tmp, final); err != nil {
		return fmt.Errorf("rename %s: %w", name, err)
	}
	return nil
}

func lookupOwner(d config.Domain) (int, int, bool) {
	if d.Owner == "" && d.Group == "" {
		return 0, 0, false
	}
	uid, gid := -1, -1
	if d.Owner != "" {
		if u, err := user.Lookup(d.Owner); err == nil {
			uid, _ = strconv.Atoi(u.Uid)
		}
	}
	if d.Group != "" {
		if g, err := user.LookupGroup(d.Group); err == nil {
			gid, _ = strconv.Atoi(g.Gid)
		}
	}
	if uid < 0 || gid < 0 {
		return 0, 0, false
	}
	return uid, gid, true
}

// writeBundle writes the requested formats. privkey is always 0600.
func writeBundle(dir string, b *pki.Bundle, d config.Domain) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir out_dir: %w", err)
	}
	mode, err := d.FileMode()
	if err != nil {
		return err
	}
	for _, f := range d.Formats {
		switch f {
		case "pem":
			if err := writeFile(dir, "fullchain.pem", b.Fullchain, mode, d); err != nil {
				return err
			}
			if err := writeFile(dir, "cert.pem", b.Cert, mode, d); err != nil {
				return err
			}
			if err := writeFile(dir, "chain.pem", b.Chain, mode, d); err != nil {
				return err
			}
			if err := writeFile(dir, "privkey.pem", b.PrivKey, 0o600, d); err != nil {
				return err
			}
		case "haproxy":
			if err := writeFile(dir, "haproxy.pem", b.Haproxy, 0o600, d); err != nil {
				return err
			}
		}
	}
	return nil
}
