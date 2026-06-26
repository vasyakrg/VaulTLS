# vaultls-agent

A certbot-style daemon that pulls TLS certificates from a [VaulTLS](https://github.com/vasyakrg/VaulTLS) server using a service account, writes them to disk in the requested formats, and runs a reload command when the certificate changes. Think of it as the deployment half of a PKI pipeline: VaulTLS issues and revokes; the agent distributes.

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

## Metrics

The agent exposes Prometheus metrics at `http://127.0.0.1:9105/metrics` (configurable via `exporter.listen`).

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

### Useful alert examples

```promql
# Certificate expires in less than 7 days
(vaultls_cert_expiry_timestamp_seconds - time()) / 86400 < 7

# Agent is down
vaultls_agent_up == 0

# New version available
vaultls_agent_update_available == 1
```

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
