package target

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/vasyakrg/vaultls-agent/internal/config"
	"github.com/vasyakrg/vaultls-agent/internal/pki"
	"github.com/vasyakrg/vaultls-agent/internal/store"
)

// File deploys a bundle as files under out_dir, with the state kept in the
// .vaultls-state.json that lives beside them.
type File struct{ d config.Domain }

func (f File) LoadState(context.Context) (store.State, error) { return store.Read(f.d.OutDir) }

func (f File) Apply(_ context.Context, b *pki.Bundle) error { return writeBundle(f.d.OutDir, b, f.d) }

func (f File) SaveState(_ context.Context, s store.State) error { return store.Write(f.d.OutDir, s) }

func (f File) Describe() string { return f.d.OutDir }

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

// lookupOwner resolves the configured owner/group to numeric ids. A -1 in
// either dimension means "preserve" for os.Chown, so only-owner or only-group
// configs are honored. Returns ok=false when nothing is configured, or when a
// configured name cannot be resolved (configured-but-unresolvable → skip chown).
func lookupOwner(d config.Domain) (int, int, bool) {
	if d.Owner == "" && d.Group == "" {
		return 0, 0, false
	}
	uid, gid := -1, -1
	if d.Owner != "" {
		u, err := user.Lookup(d.Owner)
		if err != nil {
			return 0, 0, false
		}
		uid, _ = strconv.Atoi(u.Uid)
	}
	if d.Group != "" {
		g, err := user.LookupGroup(d.Group)
		if err != nil {
			return 0, 0, false
		}
		gid, _ = strconv.Atoi(g.Gid)
	}
	return uid, gid, true
}

// Heal re-applies the configured mode and owner/group to already-deployed
// files, so a config change (or a manual chmod) takes effect without waiting
// for the certificate to be reissued. Files that do not exist are skipped —
// Apply writes them with the right metadata when the bundle next deploys.
// Unlike the best-effort chown in writeFile, a failing chown here is an
// error: the operator asked for this ownership, and silently keeping the
// drift would hide exactly the problem Heal exists to fix.
func (f File) Heal(_ context.Context) (int, error) {
	mode, err := f.d.FileMode()
	if err != nil {
		return 0, err
	}
	uid, gid, wantOwner := lookupOwner(f.d)
	fixed := 0
	for _, bf := range bundleFiles(f.d, mode) {
		path := filepath.Join(f.d.OutDir, bf.name)
		info, err := os.Stat(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return fixed, fmt.Errorf("stat %s: %w", bf.name, err)
		}
		if info.Mode().Perm() != bf.mode {
			if err := os.Chmod(path, bf.mode); err != nil {
				return fixed, fmt.Errorf("chmod %s: %w", bf.name, err)
			}
			fixed++
		}
		if curUid, curGid, ok := fileOwner(info); wantOwner && ok && ownerDiffers(curUid, curGid, uid, gid) {
			if err := os.Chown(path, uid, gid); err != nil {
				return fixed, fmt.Errorf("chown %s: %w", bf.name, err)
			}
			fixed++
		}
	}
	return fixed, nil
}

// fileOwner extracts the numeric owner from stat data. Targets are Linux
// nodes (deb + systemd), tests run on darwin; both carry *syscall.Stat_t.
func fileOwner(info os.FileInfo) (int, int, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return int(st.Uid), int(st.Gid), true
}

// ownerDiffers compares the current uid/gid against the configured ones. A -1
// dimension (owner-only or group-only config) never counts as drifted.
func ownerDiffers(curUid, curGid, wantUid, wantGid int) bool {
	if wantUid >= 0 && curUid != wantUid {
		return true
	}
	if wantGid >= 0 && curGid != wantGid {
		return true
	}
	return false
}

// bundleFile is one artifact writeBundle deploys: a file name and the mode it
// gets. Heal walks the same list, so the deployed set and the healed set can
// never drift apart.
type bundleFile struct {
	name string
	mode os.FileMode
}

// bundleFiles enumerates the artifacts for the configured formats. mode is the
// domain's file mode for certificate material; key material is always 0600.
func bundleFiles(d config.Domain, mode os.FileMode) []bundleFile {
	split := d.SplitFileNames()
	haproxy := d.HaproxyFileName()
	var out []bundleFile
	for _, f := range d.Formats {
		switch f {
		case "nginx", "pem": // "pem" is the legacy alias for the split-format layout
			out = append(out,
				bundleFile{split.Fullchain, mode},
				bundleFile{split.Cert, mode},
				bundleFile{split.Chain, mode},
				bundleFile{split.PrivKey, 0o600},
			)
		case "haproxy":
			out = append(out, bundleFile{haproxy, 0o600})
		}
	}
	return out
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
	split := d.SplitFileNames()
	data := map[string][]byte{
		split.Fullchain:     b.Fullchain,
		split.Cert:          b.Cert,
		split.Chain:         b.Chain,
		split.PrivKey:       b.PrivKey,
		d.HaproxyFileName(): b.Haproxy,
	}
	for _, f := range bundleFiles(d, mode) {
		if err := writeFile(dir, f.name, data[f.name], f.mode, d); err != nil {
			return err
		}
	}
	return nil
}
