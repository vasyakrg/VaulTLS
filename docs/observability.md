# Observability

VaulTLS exposes a Prometheus-compatible metrics endpoint at `GET /metrics`. This guide covers the metric reference, a scrape configuration, alert rules, and an Alertmanager routing example.

## Metrics reference

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `vaultls_build_info` | gauge | `version` | Always `1`. Build/version identifier for the running instance. |
| `vaultls_certificate_expiry_timestamp_seconds` | gauge | `id,cn,type,issuer` | Leaf certificate `notAfter` (unix seconds). Non-revoked certificates only. |
| `vaultls_certificates_total` | gauge | `type` | Count of certificates by type (including revoked). |
| `vaultls_certificates_expired_total` | gauge | none | Non-revoked certificates already past their expiry. |
| `vaultls_certificates_revoked_total` | gauge | none | Count of revoked certificates. |
| `vaultls_ca_expiry_timestamp_seconds` | gauge | `id,cn,type` | CA certificate `notAfter` (unix seconds). |
| `vaultls_acme_order_created_timestamp_seconds` | gauge | `id,domain,status` | Creation time of non-`valid` (in-flight/failed) ACME orders. |
| `vaultls_acme_orders_total` | gauge | `status` | Count of ACME orders by status. |

Label value conventions:

- `type` (certificates): `tls_client`, `tls_server`, `ssh_client`, `ssh_server`.
- `type` (CA): `tls`, `ssh`.
- `issuer`: `acme:<provider>`, `ca:<ca_cn>`, or `imported`.

## Prometheus scrape config

```yaml
scrape_configs:
  - job_name: vaultls
    metrics_path: /metrics
    scheme: http
    # Only if VAULTLS_METRICS_TOKEN is set:
    authorization:
      type: Bearer
      credentials: "<VAULTLS_METRICS_TOKEN>"
    scrape_interval: 60s
    static_configs:
      - targets: ["vaultls.internal:80"]
```

## Alert rules

```yaml
groups:
  - name: vaultls
    rules:
      - alert: CertExpiringSoon
        expr: vaultls_certificate_expiry_timestamp_seconds - time() < 30 * 86400
        for: 1h
        labels: { severity: warning }
        annotations:
          summary: "Certificate {{ $labels.cn }} (id {{ $labels.id }}) expires in < 30d"
      - alert: CertExpiringCritical
        expr: vaultls_certificate_expiry_timestamp_seconds - time() < 7 * 86400
        for: 1h
        labels: { severity: critical }
        annotations:
          summary: "Certificate {{ $labels.cn }} expires in < 7d"
      - alert: CertExpired
        expr: vaultls_certificate_expiry_timestamp_seconds - time() < 0
        labels: { severity: critical }
        annotations:
          summary: "Certificate {{ $labels.cn }} has EXPIRED"
      - alert: CAExpiringSoon
        expr: vaultls_ca_expiry_timestamp_seconds - time() < 30 * 86400
        for: 1h
        labels: { severity: warning }
        annotations:
          summary: "CA {{ $labels.cn }} expires in < 30d"
      - alert: AcmeOrderStuck
        expr: time() - vaultls_acme_order_created_timestamp_seconds > 3600
        for: 30m
        labels: { severity: warning }
        annotations:
          summary: "ACME order {{ $labels.id }} for {{ $labels.domain }} stuck in {{ $labels.status }}"
      - alert: VaultlsDown
        expr: up{job="vaultls"} == 0
        for: 5m
        labels: { severity: critical }
        annotations:
          summary: "VaulTLS metrics endpoint is down"
```

## Alertmanager example

```yaml
route:
  receiver: default
  group_by: ["alertname", "severity"]
  routes:
    - matchers: [ severity="critical" ]
      receiver: pager
receivers:
  - name: default
    # e.g. slack/webhook
  - name: pager
    # e.g. pagerduty/opsgenie
```

## Security note

If `VAULTLS_METRICS_TOKEN` is unset, `/metrics` is unauthenticated. Restrict access with a NetworkPolicy or firewall rule limiting who can reach the endpoint, or set `VAULTLS_METRICS_TOKEN` to require a bearer token on every scrape.
