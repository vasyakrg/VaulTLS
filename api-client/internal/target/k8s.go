package target

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/vasyakrg/vaultls-agent/internal/config"
	"github.com/vasyakrg/vaultls-agent/internal/k8s"
	"github.com/vasyakrg/vaultls-agent/internal/pki"
	"github.com/vasyakrg/vaultls-agent/internal/store"
)

// Annotation keys holding the deployment state. A pod has no writable volume to
// keep .vaultls-state.json in, and recording the state on the Secret itself
// means a restarted or rescheduled agent still skips an unchanged certificate.
const (
	annCertID      = "vaultls.io/cert-id"
	annSerial      = "vaultls.io/serial"
	annValidUntil  = "vaultls.io/valid-until"
	annLastCheck   = "vaultls.io/last-check"
	annLastRenewal = "vaultls.io/last-renewal"

	labelManagedBy = "app.kubernetes.io/managed-by"
	managedByValue = "vaultls-agent"

	secretTypeTLS = "kubernetes.io/tls"
)

// K8s keeps one Secret in sync with the certificate. Replication to other
// namespaces is deliberately out of scope: cluster tooling (Kyverno, reflector)
// does that better, selecting the source by the labels configured here.
type K8s struct {
	c *k8s.Client
	d config.Domain
}

func (t K8s) Describe() string { return t.d.K8s.Namespace + "/" + t.d.K8s.Secret }

func (t K8s) LoadState(ctx context.Context) (store.State, error) {
	s, err := t.c.GetSecret(ctx, t.d.K8s.Namespace, t.d.K8s.Secret)
	if errors.Is(err, k8s.ErrNotFound) {
		return store.State{}, nil
	}
	if err != nil {
		return store.State{}, fmt.Errorf("get secret %s: %w", t.Describe(), err)
	}
	a := s.Metadata.Annotations
	return store.State{
		CertID:      atoi(a[annCertID]),
		Serial:      a[annSerial],
		ValidUntil:  atoi(a[annValidUntil]),
		LastCheck:   atoi(a[annLastCheck]),
		LastRenewal: atoi(a[annLastRenewal]),
	}, nil
}

func (t K8s) Apply(ctx context.Context, b *pki.Bundle) error {
	_, err := t.c.GetSecret(ctx, t.d.K8s.Namespace, t.d.K8s.Secret)
	switch {
	case errors.Is(err, k8s.ErrNotFound):
		return t.create(ctx, b)
	case err != nil:
		return fmt.Errorf("get secret %s: %w", t.Describe(), err)
	}
	return t.patchData(ctx, b)
}

func (t K8s) SaveState(ctx context.Context, s store.State) error {
	patch, err := json.Marshal(map[string]any{
		"metadata": map[string]any{"annotations": stateAnnotations(s)},
	})
	if err != nil {
		return fmt.Errorf("encode state patch: %w", err)
	}
	if err := t.c.PatchSecret(ctx, t.d.K8s.Namespace, t.d.K8s.Secret, patch); err != nil {
		return fmt.Errorf("patch secret %s: %w", t.Describe(), err)
	}
	return nil
}

func (t K8s) create(ctx context.Context, b *pki.Bundle) error {
	s := &k8s.Secret{
		Metadata: k8s.ObjectMeta{
			Name:      t.d.K8s.Secret,
			Namespace: t.d.K8s.Namespace,
			Labels:    t.labels(),
		},
		Type: secretTypeTLS,
		Data: t.data(b),
	}
	if err := t.c.CreateSecret(ctx, s); err != nil {
		return fmt.Errorf("create secret %s: %w", t.Describe(), err)
	}
	return nil
}

// patchData sends a merge patch carrying only the keys the agent owns, so
// labels and annotations added by other controllers are preserved. The Secret
// type is immutable and therefore never patched.
func (t K8s) patchData(ctx context.Context, b *pki.Bundle) error {
	patch, err := json.Marshal(map[string]any{
		"metadata": map[string]any{"labels": t.labels()},
		"data":     t.dataPatch(b),
	})
	if err != nil {
		return fmt.Errorf("encode secret patch: %w", err)
	}
	if err := t.c.PatchSecret(ctx, t.d.K8s.Namespace, t.d.K8s.Secret, patch); err != nil {
		return fmt.Errorf("patch secret %s: %w", t.Describe(), err)
	}
	return nil
}

// data is the kubernetes.io/tls payload.
func (t K8s) data(b *pki.Bundle) map[string][]byte {
	d := map[string][]byte{
		"tls.crt": b.Fullchain,
		"tls.key": b.PrivKey,
	}
	if t.d.K8s.IncludeCA {
		d["ca.crt"] = b.Chain
	}
	return d
}

// dataPatch is data in merge-patch form. With include_ca off, ca.crt is sent as
// an explicit null — which a merge patch reads as "delete this key" — so
// turning the option off actually drops a chain written by an earlier run.
func (t K8s) dataPatch(b *pki.Bundle) map[string]any {
	d := map[string]any{}
	for k, v := range t.data(b) {
		d[k] = v
	}
	if !t.d.K8s.IncludeCA {
		d["ca.crt"] = nil
	}
	return d
}

func (t K8s) labels() map[string]string {
	l := map[string]string{labelManagedBy: managedByValue}
	for k, v := range t.d.K8s.Labels {
		l[k] = v
	}
	return l
}

func stateAnnotations(s store.State) map[string]string {
	return map[string]string{
		annCertID:      strconv.FormatInt(s.CertID, 10),
		annSerial:      s.Serial,
		annValidUntil:  strconv.FormatInt(s.ValidUntil, 10),
		annLastCheck:   strconv.FormatInt(s.LastCheck, 10),
		annLastRenewal: strconv.FormatInt(s.LastRenewal, 10),
	}
}

func atoi(s string) int64 {
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0
	}
	return v
}
