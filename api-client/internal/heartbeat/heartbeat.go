// Package heartbeat reports the agent's status snapshot to the server
// (POST /api/agents/heartbeat). Sends are best-effort: a failure is logged by
// the caller and retried by the next tick — heartbeat must never interfere
// with certificate deployment.
package heartbeat

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/vasyakrg/vaultls-agent/internal/status"
)

// Poster is the slice of the API client the reporter needs.
type Poster interface {
	PostJSON(ctx context.Context, path string, payload any) error
}

// Meta carries the run-level facts embedded in every payload.
type Meta struct {
	Version     string
	Schedule    string
	IntervalSec int64
	CATrustOn   bool
}

// Payload is the wire contract with POST /api/agents/heartbeat; the server
// derives the agent's row identity from the service token plus AgentID.
type Payload struct {
	AgentID              string          `json:"agent_id"`
	Version              string          `json:"version"`
	Hostname             string          `json:"hostname"`
	OS                   string          `json:"os"`
	Arch                 string          `json:"arch"`
	Schedule             string          `json:"schedule"`
	HeartbeatIntervalSec int64           `json:"heartbeat_interval_sec"`
	CATrustEnabled       bool            `json:"ca_trust_enabled"`
	Domains              []status.Domain `json:"domains"`
}

// Reporter builds and sends heartbeats. AgentID override exists for pods: a
// generated file under a container filesystem dies with the pod and would
// show up as a new agent on every restart.
type Reporter struct {
	api      Poster
	tracker  *status.Tracker
	meta     Meta
	override string
	stateDir string
}

func NewReporter(api Poster, tracker *status.Tracker, meta Meta, agentIDOverride, stateDir string) *Reporter {
	return &Reporter{api: api, tracker: tracker, meta: meta, override: agentIDOverride, stateDir: stateDir}
}

// Send reports the current snapshot once.
func (r *Reporter) Send(ctx context.Context) error {
	id, err := r.agentID()
	if err != nil {
		return err
	}
	hostname, _ := os.Hostname() // best-effort label; an error leaves ""
	p := Payload{
		AgentID:              id,
		Version:              r.meta.Version,
		Hostname:             hostname,
		OS:                   runtime.GOOS,
		Arch:                 runtime.GOARCH,
		Schedule:             r.meta.Schedule,
		HeartbeatIntervalSec: r.meta.IntervalSec,
		CATrustEnabled:       r.meta.CATrustOn,
		Domains:              r.tracker.Snapshot(),
	}
	return r.api.PostJSON(ctx, "/api/agents/heartbeat", p)
}

// agentID returns the configured override, or the locally generated UUID,
// creating it on first use.
func (r *Reporter) agentID() (string, error) {
	if r.override != "" {
		return r.override, nil
	}
	path := filepath.Join(r.stateDir, "agent-id")
	if raw, err := os.ReadFile(path); err == nil {
		if id := trimSpaces(string(raw)); id != "" {
			return id, nil
		}
	}
	if err := os.MkdirAll(r.stateDir, 0o700); err != nil {
		return "", err
	}
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40 // UUID v4 marker, so the id reads as a UUID
	b[8] = (b[8] & 0x3f) | 0x80
	id := hex.EncodeToString(b[:])
	if err := os.WriteFile(path, []byte(id), 0o600); err != nil {
		return "", err
	}
	return id, nil
}

func trimSpaces(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\n' || s[start] == '\r' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\n' || s[end-1] == '\r' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}

// Run blocks sending heartbeats every interval until ctx is done. Failures
// are logged and never returned: the loop outlives any single bad request.
func (r *Reporter) Run(ctx context.Context, interval time.Duration, log *slog.Logger) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := r.Send(ctx); err != nil {
				log.Warn("heartbeat failed", "err", err)
			}
		}
	}
}
