// Package target abstracts where a reconciled certificate bundle lands: files
// under out_dir on a node, or a Secret in a Kubernetes cluster. Selecting the
// certificate, decoding it and deciding whether anything changed stays in
// package reconcile — only the deployment step differs per target.
package target

import (
	"context"
	"fmt"
	"sync"

	"github.com/vasyakrg/vaultls-agent/internal/config"
	"github.com/vasyakrg/vaultls-agent/internal/k8s"
	"github.com/vasyakrg/vaultls-agent/internal/pki"
	"github.com/vasyakrg/vaultls-agent/internal/store"
)

type Target interface {
	// LoadState returns the state recorded by the previous deployment, or the
	// zero State when nothing has been deployed yet.
	LoadState(ctx context.Context) (store.State, error)
	// Apply deploys the bundle.
	Apply(ctx context.Context, b *pki.Bundle) error
	// SaveState records the state of the current deployment.
	SaveState(ctx context.Context, s store.State) error
	// Describe identifies the destination in logs and metric labels.
	Describe() string
}

// Factory builds the target for a domain entry. The cluster client is created
// on first use, so the same binary running as a .deb on a plain node never
// looks for a service account it does not have.
type Factory struct {
	newClient func() (*k8s.Client, error)

	once   sync.Once
	client *k8s.Client
	err    error
}

func NewFactory() *Factory { return &Factory{newClient: k8s.InCluster} }

// NewFactoryWithClient injects a prepared client; used by tests.
func NewFactoryWithClient(c *k8s.Client) *Factory {
	return &Factory{newClient: func() (*k8s.Client, error) { return c, nil }}
}

func (f *Factory) cluster() (*k8s.Client, error) {
	f.once.Do(func() { f.client, f.err = f.newClient() })
	return f.client, f.err
}

func (f *Factory) For(d config.Domain) (Target, error) {
	switch d.Kind() {
	case config.TargetFile:
		return File{d: d}, nil
	case config.TargetK8s:
		c, err := f.cluster()
		if err != nil {
			return nil, fmt.Errorf("kubernetes client: %w", err)
		}
		return K8s{c: c, d: d}, nil
	default:
		return nil, fmt.Errorf("unknown target %q", d.Target)
	}
}
