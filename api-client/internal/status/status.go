// Package status keeps the last reconcile outcome per configured domain so the
// heartbeat can report it to the server. Prometheus counters already track
// error rates, but they are write-only from the callers' perspective — the
// heartbeat payload needs readable values.
package status

import (
	"sort"
	"sync"
)

// Domain is the last reconcile outcome for one config entry, mirrored to the
// server in the heartbeat. Field names are the wire contract with
// POST /api/agents/heartbeat.
type Domain struct {
	Name        string `json:"name"`
	CertID      int64  `json:"cert_id"`
	Target      string `json:"target"`
	Destination string `json:"destination"`
	Status      string `json:"status"` // "ok" | "error"
	Stage       string `json:"stage,omitempty"`
	Error       string `json:"error,omitempty"`
	Serial      string `json:"serial,omitempty"`
	ExpiryMS    int64  `json:"expiry_ms,omitempty"`
	LastCheckMS int64  `json:"last_check_ms"`
}

// Tracker is a concurrency-safe map of the latest Domain status keyed by the
// target's destination (unique per config — the validator rejects two entries
// deploying to one destination). Entries appear after the domain's first
// reconcile pass.
type Tracker struct {
	mu      sync.Mutex
	entries map[string]Domain
}

func New() *Tracker {
	return &Tracker{entries: map[string]Domain{}}
}

// Observe records the latest outcome for a destination.
func (t *Tracker) Observe(d Domain) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.entries[d.Destination] = d
}

// Snapshot returns all entries sorted by name, ready for the heartbeat payload.
func (t *Tracker) Snapshot() []Domain {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]Domain, 0, len(t.entries))
	for _, d := range t.entries {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Destination < out[j].Destination
	})
	return out
}
