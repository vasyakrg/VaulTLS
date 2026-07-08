# vaultls-agent

A certbot-style daemon that pulls TLS certificates from a [VaulTLS](https://github.com/vasyakrg/VaulTLS) server using a service account, writes them to disk in the requested formats, and runs a reload command when the certificate changes. Think of it as the deployment half of a PKI pipeline: VaulTLS issues and revokes; the agent distributes.

Built for Debian/amd64 hosts: ships as a single static binary in a `.deb`, runs under systemd, and exposes its state over a built-in Prometheus exporter.

---

## Capabilities

- **Pull-based distribution** — fetches certificates from VaulTLS over its REST API using a service account (`client_id` + `secret`); no inbound access to the host required.
- **Multiple domains per host** — each domain is reconciled independently; one failing domain never blocks the others.
- **Wildcard-aware lookup** — match a certificate by name (`*.example.com`) or pin an exact `cert_id`.
- **Multiple on-disk formats** — `pem` (separate `fullchain`/`privkey`/`cert`/`chain`) and `haproxy` (cert+key in one file). Private keys are always written `0600`.
- **Change detection** — compares the certificate serial against a local state file and **only reloads the target service when the certificate actually changed** — no needless reloads.
- **Atomic, fail-safe writes** — new files are written to a temp path and renamed; a server outage or a bad download never clobbers good certs already on disk.
- **Resilient API client** — in-memory token caching, one automatic re-auth on `401`, and bounded exponential backoff on transient network/5xx errors.
- **Scheduling** — internal cron-spec scheduler with optional jitter (default: monthly).
- **Observability** — Prometheus metrics for expiry, last check/renewal, reconcile/reload errors, and auth failures.
- **Self-update awareness** — checks GitHub Releases on start and daily, surfacing an `update_available` metric (informational; never auto-updates).

---

## How it works

On each scheduled run (and once at startup) the agent reconciles every configured domain:

1. Authenticate to VaulTLS (`POST /api/auth/token`) and list certificates (`GET /api/certificates`).
2. Select the target certificate — newest non-revoked match for `name`, or the exact `cert_id`.
3. **Cheap skip:** if the certificate identity (`cert_id` + `valid_until`) is unchanged from the local state, do nothing.
4. Otherwise download the PKCS#12 bundle and its password, decode to PEM, and extract the serial.
5. If the serial differs from the deployed one, atomically write the configured formats, update the state file, and run the `reload` command. If it matches, skip the reload.

Because VaulTLS issues a renewal as a **new** certificate record (new id / validity), step 3 reliably detects renewals without re-downloading on every run.

---

## Prerequisites

- A VaulTLS **service account** with the `cert:read` scope. Create it in the VaulTLS web UI (Service Accounts) and copy the `client_id` and one-time `secret`.
- The host must be able to reach the VaulTLS server over HTTPS.

---

## Install

Download the `.deb` from [GitHub Releases](https://github.com/vasyakrg/VaulTLS/releases) and install:

```bash
sudo dpkg -i vaultls-agent_<ver>_amd64.deb
# or
sudo apt install ./vaultls-agent_<ver>_amd64.deb
```

The package ships a systemd unit (`vaultls-agent.service`) that is **not** automatically started. Run `vaultls-agent setup` to generate the config and optionally enable the service.

---

## First-run setup

```bash
sudo vaultls-agent setup \
  --url https://vaultls.example.com \
  --client-id svc_xxxxxxxx \
  --secret YOUR_SECRET \
  --domain "*.example.com" \
  --reload "systemctl reload nginx"
```

| Flag | Default | Description |
|---|---|---|
| `--url` | — | VaulTLS server URL |
| `--client-id` | — | Service account client ID |
| `--secret` | — | Service account secret |
| `--domain` | — | Certificate name (e.g. `*.example.com`) |
| `--reload` | — | Shell command to run after certificate update |
| `--out` | `/etc/vaultls/config.yaml` | Where to write the generated config |
| `--enable` | `true` | Run `systemctl enable --now vaultls-agent` after writing config |

**Non-interactive mode:** all five required flags (`--url`, `--client-id`, `--secret`, `--domain`, `--reload`) must be supplied together. If any is missing the command drops into an interactive wizard that prompts for each value.

The generated config is written with permissions `0600`. The directory is created if absent.

---

## Commands

| Command | Description |
|---|---|
| `vaultls-agent run` | Start the daemon (used by the systemd unit). Runs on the configured cron schedule. |
| `vaultls-agent run --once` | Same as `check` — one reconcile pass, then exit. |
| `vaultls-agent setup [flags]` | Generate `/etc/vaultls/config.yaml` and optionally enable the service. |
| `vaultls-agent check [--config <path>]` | Run a single reconcile pass and exit. Useful for cron or smoke-testing. |
| `vaultls-agent version` | Print the build version. |

All commands that read config accept `--config <path>` (default: `/etc/vaultls/config.yaml`).

---

## Configuration reference

Config file: `/etc/vaultls/config.yaml` (created by `setup`; owned root, mode `0600`).

### Server block

| Field | Type | Description |
|---|---|---|
| `server.url` | string | VaulTLS server base URL (e.g. `https://vaultls.example.com`) |
| `server.client_id` | string | Service account client ID |
| `server.secret` | string | Service account secret. Supports `${ENV_VAR}` substitution. |
| `server.insecure_skip_verify` | bool | Skip TLS verification. **Not recommended in production.** |

### Top-level fields

| Field | Type | Description |
|---|---|---|
| `schedule` | cron expression | When to run the reconcile loop (e.g. `"0 3 1 * *"` = 03:00 on the 1st of each month). |
| `jitter` | duration string | Random delay added to each scheduled run to avoid thundering-herd (e.g. `30m`). |
| `log.level` | string | Log verbosity: `debug`, `info` (default), `warn`, `error`. |
| `log.format` | string | Log format: `text` (default) or `json`. |
| `log.file` | string | Optional file path. When set, logs are written there (e.g. `/var/log/vaultls-agent.log`) instead of stderr. Unset → stderr, captured by journald (`journalctl -u vaultls-agent`). |
| `exporter.listen` | `host:port` | Address for the Prometheus `/metrics` endpoint. Default: `127.0.0.1:9105`. |

### Domain entries (`domains[]`)

| Field | Type | Description |
|---|---|---|
| `name` | string | VaulTLS certificate name to look up (see wildcard note below). |
| `out_dir` | string | Directory where certificate files are written. |
| `formats` | `[]string` | Output formats: `pem`, `haproxy` (both may be listed). |
| `owner` | string | File owner for written certificate files. |
| `group` | string | File group for written certificate files. |
| `mode` | octal string | File permissions for non-private files (default `"0640"`). Private key is always `0600`. |
| `reload` | string | Shell command executed after a certificate is updated. |
| `cert_id` | int64 | If non-zero, selects a certificate by its exact ID instead of by `name`. |

### Wildcard mapping

`name` is matched against the certificate name stored in VaulTLS. For wildcard certificates use the literal name with the asterisk, e.g.:

```yaml
name: "*.example.com"
```

The agent automatically selects the **newest non-revoked** certificate with that name. Set `cert_id` to pin a specific certificate by its database ID, bypassing the name lookup entirely.

---

## Output files

Files are written to `out_dir`. The state file `.vaultls-state.json` in each `out_dir` records the last-deployed serial and is used to skip unnecessary writes.

### `pem` format

| File | Permissions | Contents |
|---|---|---|
| `fullchain.pem` | `mode` | Certificate + intermediate chain (PEM) |
| `privkey.pem` | `0600` | Private key (PEM) |
| `cert.pem` | `mode` | End-entity certificate only (PEM) |
| `chain.pem` | `mode` | Intermediate chain only (PEM) |

### `haproxy` format

| File | Permissions | Contents |
|---|---|---|
| `haproxy.pem` | `0600` | Fullchain + private key concatenated (HAProxy `crt` format) |

---

## systemd and `ReadWritePaths`

The shipped unit uses `ProtectSystem=full`, which makes `/usr`, `/boot`, and `/etc` read-only **except** for the explicitly listed paths:

```
ReadWritePaths=/etc/ssl/vaultls /etc/vaultls
```

Any `out_dir` outside `/etc/ssl/vaultls` will fail to write at runtime. To allow additional paths, create a drop-in override:

```bash
sudo systemctl edit vaultls-agent
```

Add:

```ini
[Service]
ReadWritePaths+=/your/custom/out_dir
```

Save and reload: `sudo systemctl daemon-reload && sudo systemctl restart vaultls-agent`.

---

## Metrics & exporter

The agent embeds a Prometheus exporter — there is no separate process. It serves
`GET /metrics` on `exporter.listen` (default `http://127.0.0.1:9105/metrics`) for the
whole lifetime of the daemon. Metrics are updated on every reconcile pass and on each
daily self-update check, so the endpoint always reflects current state even between
scheduled runs.

By default it binds to loopback (`127.0.0.1`) so metrics are not exposed off-host;
point your Prometheus at it locally, scrape via a node-exporter-style sidecar, or set
`exporter.listen: "0.0.0.0:9105"` (behind a firewall) to scrape remotely.

| Metric | Type | Labels | Description |
|---|---|---|---|
| `vaultls_agent_up` | Gauge | — | `1` while the agent process is running |
| `vaultls_agent_build_info` | Gauge | `version` | Build version info (value always `1`) |
| `vaultls_agent_update_available` | Gauge | — | `1` if a newer GitHub release exists |
| `vaultls_agent_latest_version_info` | Gauge | `version` | Latest known release tag (value always `1`) |
| `vaultls_cert_expiry_timestamp_seconds` | Gauge | `domain` | Certificate `NotAfter` as a Unix timestamp |
| `vaultls_cert_serial_info` | Gauge | `domain`, `serial` | Current deployed certificate serial (value always `1`) |
| `vaultls_last_check_timestamp_seconds` | Gauge | `domain` | Unix timestamp of the last reconcile check |
| `vaultls_last_renewal_timestamp_seconds` | Gauge | `domain` | Unix timestamp of the last actual certificate write |
| `vaultls_reconcile_errors_total` | Counter | `domain`, `stage` | Reconcile errors by domain and pipeline stage |
| `vaultls_reload_failures_total` | Counter | `domain` | Reload command failures |
| `vaultls_scrape_token_errors_total` | Counter | — | Authentication/token errors against the VaulTLS API |

### Prometheus scrape config

```yaml
scrape_configs:
  - job_name: vaultls-agent
    static_configs:
      - targets: ["127.0.0.1:9105"]
```

### Alerting rules (Prometheus → Alertmanager)

Drop this into a Prometheus rule file (e.g. `vaultls-agent.rules.yml`) referenced from
`rule_files:` in `prometheus.yml`. Firing alerts are forwarded to Alertmanager by
Prometheus as usual — no agent-side config is required.

```yaml
groups:
  - name: vaultls-agent
    rules:
      # --- Availability ---
      - alert: VaultlsAgentDown
        expr: vaultls_agent_up == 0
        for: 5m
        labels: { severity: critical }
        annotations:
          summary: "vaultls-agent is down on {{ $labels.instance }}"
          description: "The exporter has not reported up=1 for 5 minutes."

      - alert: VaultlsAgentNoMetrics
        expr: up{job="vaultls-agent"} == 0
        for: 10m
        labels: { severity: critical }
        annotations:
          summary: "vaultls-agent exporter unreachable ({{ $labels.instance }})"
          description: "Prometheus cannot scrape the agent's /metrics endpoint."

      # --- Certificate expiry ---
      - alert: VaultlsCertExpiringSoon
        expr: (vaultls_cert_expiry_timestamp_seconds - time()) / 86400 < 14
        for: 1h
        labels: { severity: warning }
        annotations:
          summary: "Certificate for {{ $labels.domain }} expires in < 14 days"
          description: "Renew/issue in VaulTLS; the agent will pull it on the next run."

      - alert: VaultlsCertExpiringCritical
        expr: (vaultls_cert_expiry_timestamp_seconds - time()) / 86400 < 3
        for: 30m
        labels: { severity: critical }
        annotations:
          summary: "Certificate for {{ $labels.domain }} expires in < 3 days"

      - alert: VaultlsCertExpired
        expr: vaultls_cert_expiry_timestamp_seconds - time() <= 0
        for: 5m
        labels: { severity: critical }
        annotations:
          summary: "Certificate for {{ $labels.domain }} has EXPIRED"

      # --- Reconcile / deployment health ---
      - alert: VaultlsReconcileErrors
        expr: increase(vaultls_reconcile_errors_total[1h]) > 0
        for: 5m
        labels: { severity: warning }
        annotations:
          summary: "Reconcile errors for {{ $labels.domain }} (stage {{ $labels.stage }})"
          description: "The agent failed to fetch/decode/write a certificate."

      - alert: VaultlsReloadFailing
        expr: increase(vaultls_reload_failures_total[1h]) > 0
        for: 5m
        labels: { severity: critical }
        annotations:
          summary: "Reload command failing for {{ $labels.domain }}"
          description: "A new certificate was written but the service reload failed — the service may still serve the old certificate."

      - alert: VaultlsAuthErrors
        expr: increase(vaultls_scrape_token_errors_total[1h]) > 0
        for: 15m
        labels: { severity: warning }
        annotations:
          summary: "VaulTLS authentication errors on {{ $labels.instance }}"
          description: "Check the service account client_id/secret and the cert:read scope."

      # --- Staleness: reconcile loop not running ---
      - alert: VaultlsReconcileStale
        expr: time() - vaultls_last_check_timestamp_seconds > 40 * 86400
        for: 1h
        labels: { severity: warning }
        annotations:
          summary: "No reconcile check for {{ $labels.domain }} in > 40 days"
          description: "Expected at least monthly. The scheduler may be stuck or the daemon restarting."

      # --- Update awareness (informational) ---
      - alert: VaultlsAgentUpdateAvailable
        expr: vaultls_agent_update_available == 1
        for: 24h
        labels: { severity: info }
        annotations:
          summary: "A newer vaultls-agent release is available"
          description: "Check vaultls_agent_latest_version_info for the latest release tag."
```

Tune thresholds (expiry windows, staleness vs your `schedule`) to your environment.
The `VaultlsReloadFailing` alert is the most operationally important: it means a fresh
certificate is on disk but the service wasn't reloaded, so it may still serve the old one.

---

## Automatic update checks

On startup and once per day the agent queries the GitHub Releases API (`vasyakrg/VaulTLS`) for the latest release tag. The result is reflected in:

- `vaultls_agent_update_available` — `1` if a newer version exists
- `vaultls_agent_latest_version_info{version="v0.x.y"}` — the latest tag

No automatic download or installation is performed; the metrics are informational only.

---

## Example config

```yaml
server:
  url: https://vaultls.example.com
  client_id: svc_xxxxxxxx
  secret: ${VAULTLS_SECRET}
  insecure_skip_verify: false
schedule: "0 3 1 * *"
jitter: 30m
exporter:
  listen: "127.0.0.1:9105"
domains:
  - name: "*.example.com"
    out_dir: /etc/ssl/vaultls/example.com
    formats: [pem, haproxy]
    owner: root
    group: ssl-cert
    mode: "0640"
    reload: "systemctl reload nginx"
```

Secrets may be supplied via environment variables using `${VAR}` syntax in the config file.

### Multiple domains

A single agent can manage any number of domains, each with its own output directory, formats and reload command:

```yaml
server:
  url: https://vaultls.example.com
  client_id: svc_xxxxxxxx
  secret: ${VAULTLS_SECRET}
schedule: "0 3 1 * *"
jitter: 30m
exporter:
  listen: "127.0.0.1:9105"
domains:
  - name: "*.example.com"
    out_dir: /etc/ssl/vaultls/example.com
    formats: [pem]
    reload: "systemctl reload nginx"
  - name: "*.internal.example.com"
    out_dir: /etc/ssl/vaultls/internal
    formats: [haproxy]
    owner: haproxy
    reload: "systemctl reload haproxy"
  - cert_id: 42          # pin an exact certificate by ID instead of by name
    out_dir: /etc/ssl/vaultls/legacy
    formats: [pem]
    reload: "systemctl reload postfix"
```

---

## Logs & troubleshooting

The daemon logs to the journal:

```bash
# Follow live logs
journalctl -u vaultls-agent -f

# Service status
systemctl status vaultls-agent

# Force a single reconcile pass without waiting for the schedule
sudo vaultls-agent check
```

Common issues:

| Symptom | Likely cause |
|---|---|
| `no certificate found for ...` | `name` doesn't match a VaulTLS certificate, or it's revoked. Check the name (wildcards must be literal, e.g. `*.example.com`) or pin `cert_id`. |
| Auth errors (`vaultls_scrape_token_errors_total` rising) | Wrong `client_id`/`secret`, or the service account lacks the `cert:read` scope. |
| Files not written despite a new cert | `out_dir` is outside `ReadWritePaths` (see the systemd section) — the write is blocked by `ProtectSystem=full`. |
| Reload never runs | The certificate serial hasn't changed — by design the reload only fires on a real change. |

---

## Build from source

Requires Go 1.26+.

```bash
cd api-client

# Run the test suite
make test            # or: go test ./...

# Build the Linux/amd64 binary
make build VERSION=0.1.0

# Build the .deb (requires nfpm: go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest)
make deb VERSION=0.1.0
```

The resulting package and binary land in `api-client/dist/` (git-ignored).
