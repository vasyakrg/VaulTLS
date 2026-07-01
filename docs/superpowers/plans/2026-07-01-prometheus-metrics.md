# VaulTLS Prometheus Metrics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expose a `GET /metrics` Prometheus endpoint that reports certificate/CA expiry timestamps and ACME renewal problems, computed on scrape from the DB, plus alerting docs and Helm wiring.

**Architecture:** A pure formatter (`metrics.rs`) renders Prometheus text exposition from plain input structs (fully unit-tested, with label-value escaping). The route gathers certs/CAs/ACME orders from the DB, maps them to those structs, and returns the rendered body. A lightweight `MetricsAuth` guard optionally requires a bearer token. Docs and Helm complete the feature.

**Tech Stack:** Rust (Rocket, rusqlite), no `prometheus` crate. Prometheus/Alertmanager (docs). Helm.

## Global Constraints

- Prometheus text exposition format 0.0.4; timestamps in unix **seconds** (`valid_until`/`created_on` in DB are **milliseconds** → divide by 1000).
- Label-value escaping (Prometheus spec): `\` → `\\`, `"` → `\"`, newline → `\n`.
- Metric names exactly: `vaultls_build_info`, `vaultls_certificate_expiry_timestamp_seconds`, `vaultls_certificates_total`, `vaultls_certificates_expired_total`, `vaultls_certificates_revoked_total`, `vaultls_ca_expiry_timestamp_seconds`, `vaultls_acme_order_created_timestamp_seconds`, `vaultls_acme_orders_total`.
- `type` label values: certs `tls_client|tls_server|ssh_client|ssh_server`; CA `tls|ssh`.
- `issuer` label: `acme:<provider_name>` if `acme_provider_id` set, else `ca:<ca_cn>` if `ca_id` set, else `imported`.
- Endpoint auth: env `VAULTLS_METRICS_TOKEN` read via `std::env::var`; trimmed empty = unset = open; if set, require `Authorization: Bearer <token>` (else HTTP 401).
- `/metrics` mounted at `/` (root) via plain `routes![metrics]` (NOT `openapi_get_routes!`).
- Backend compiles clean, ZERO warnings (`cargo build` from `backend/`).
- Work on branch `feat/prometheus-metrics` (already checked out). Local commits only; do NOT push.
- Enum variants: `CertificateType::{TLSClient,TLSServer,SSHClient,SSHServer}`, `CAType::{TLS,SSH}`. `Name` has `.cn: String`. `crate::constants::VAULTLS_VERSION` is the version string.

---

### Task 1: Pure metrics formatter + escaping

**Files:**
- Create: `backend/src/metrics.rs`
- Modify: `backend/src/lib.rs` (add `mod metrics;`)

**Interfaces:**
- Produces:
  - `pub(crate) struct CertMetric { pub id: i64, pub cn: String, pub cert_type: &'static str, pub issuer: String, pub expiry_seconds: i64, pub revoked: bool }`
  - `pub(crate) struct CaMetric { pub id: i64, pub cn: String, pub ca_type: &'static str, pub expiry_seconds: i64 }`
  - `pub(crate) struct AcmeOrderMetric { pub id: i64, pub domain: String, pub status: String, pub created_seconds: i64 }`
  - `pub(crate) fn render_metrics(version: &str, certs: &[CertMetric], cas: &[CaMetric], orders: &[AcmeOrderMetric]) -> String`
  - `fn escape_label_value(v: &str) -> String`

- [ ] **Step 1: Write the failing tests**

Create `backend/src/metrics.rs` with ONLY a `#[cfg(test)] mod tests` block first (so the test fails to compile against missing items):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_label_values() {
        assert_eq!(escape_label_value(r#"a"b\c"#), r#"a\"b\\c"#);
        assert_eq!(escape_label_value("line1\nline2"), r"line1\nline2");
        assert_eq!(escape_label_value("plain"), "plain");
    }

    #[test]
    fn renders_build_info_and_cert() {
        let certs = vec![CertMetric {
            id: 7,
            cn: "novotelecom.ru".into(),
            cert_type: "tls_server",
            issuer: "acme:Let's Encrypt".into(),
            expiry_seconds: 1_730_419_200,
            revoked: false,
        }];
        let out = render_metrics("v1.2.3", &certs, &[], &[]);
        assert!(out.contains("# TYPE vaultls_build_info gauge"));
        assert!(out.contains(r#"vaultls_build_info{version="v1.2.3"} 1"#));
        assert!(out.contains(
            r#"vaultls_certificate_expiry_timestamp_seconds{id="7",cn="novotelecom.ru",type="tls_server",issuer="acme:Let's Encrypt"} 1730419200"#
        ));
        // aggregate present
        assert!(out.contains(r#"vaultls_certificates_total{type="tls_server"} 1"#));
    }

    #[test]
    fn revoked_excluded_from_expiry_but_counted() {
        let certs = vec![CertMetric {
            id: 1, cn: "r".into(), cert_type: "tls_client", issuer: "imported".into(),
            expiry_seconds: 100, revoked: true,
        }];
        let out = render_metrics("v0", &certs, &[], &[]);
        assert!(!out.contains("vaultls_certificate_expiry_timestamp_seconds{id=\"1\""));
        assert!(out.contains("vaultls_certificates_revoked_total 1"));
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd backend && cargo test --lib metrics:: 2>&1 | tail -15`
Expected: FAIL — compile errors (missing `escape_label_value`, `render_metrics`, structs).

- [ ] **Step 3: Implement the formatter**

Prepend to `backend/src/metrics.rs` (above the test module):

```rust
//! Prometheus text-exposition metrics, computed on scrape.

pub(crate) struct CertMetric {
    pub id: i64,
    pub cn: String,
    pub cert_type: &'static str,
    pub issuer: String,
    pub expiry_seconds: i64,
    pub revoked: bool,
}

pub(crate) struct CaMetric {
    pub id: i64,
    pub cn: String,
    pub ca_type: &'static str,
    pub expiry_seconds: i64,
}

pub(crate) struct AcmeOrderMetric {
    pub id: i64,
    pub domain: String,
    pub status: String,
    pub created_seconds: i64,
}

fn escape_label_value(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for c in v.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            _ => out.push(c),
        }
    }
    out
}

/// Render the full exposition body. Deterministic ordering (input order preserved).
pub(crate) fn render_metrics(
    version: &str,
    certs: &[CertMetric],
    cas: &[CaMetric],
    orders: &[AcmeOrderMetric],
) -> String {
    use std::collections::BTreeMap;
    use std::fmt::Write;
    let mut s = String::new();

    // build_info
    let _ = writeln!(s, "# HELP vaultls_build_info VaulTLS build information.");
    let _ = writeln!(s, "# TYPE vaultls_build_info gauge");
    let _ = writeln!(s, "vaultls_build_info{{version=\"{}\"}} 1", escape_label_value(version));

    // certificate expiry (non-revoked only)
    let _ = writeln!(s, "# HELP vaultls_certificate_expiry_timestamp_seconds Leaf certificate notAfter as unix seconds.");
    let _ = writeln!(s, "# TYPE vaultls_certificate_expiry_timestamp_seconds gauge");
    for c in certs.iter().filter(|c| !c.revoked) {
        let _ = writeln!(
            s,
            "vaultls_certificate_expiry_timestamp_seconds{{id=\"{}\",cn=\"{}\",type=\"{}\",issuer=\"{}\"}} {}",
            c.id, escape_label_value(&c.cn), c.cert_type, escape_label_value(&c.issuer), c.expiry_seconds
        );
    }

    // certificates_total{type}
    let mut by_type: BTreeMap<&'static str, i64> = BTreeMap::new();
    for c in certs {
        *by_type.entry(c.cert_type).or_insert(0) += 1;
    }
    let _ = writeln!(s, "# HELP vaultls_certificates_total Total certificates by type.");
    let _ = writeln!(s, "# TYPE vaultls_certificates_total gauge");
    for (t, n) in &by_type {
        let _ = writeln!(s, "vaultls_certificates_total{{type=\"{t}\"}} {n}");
    }

    // expired / revoked aggregates
    let now = crate::helper::now_seconds();
    let expired = certs.iter().filter(|c| !c.revoked && c.expiry_seconds < now).count();
    let revoked = certs.iter().filter(|c| c.revoked).count();
    let _ = writeln!(s, "# HELP vaultls_certificates_expired_total Non-revoked certificates already expired.");
    let _ = writeln!(s, "# TYPE vaultls_certificates_expired_total gauge");
    let _ = writeln!(s, "vaultls_certificates_expired_total {expired}");
    let _ = writeln!(s, "# HELP vaultls_certificates_revoked_total Revoked certificates.");
    let _ = writeln!(s, "# TYPE vaultls_certificates_revoked_total gauge");
    let _ = writeln!(s, "vaultls_certificates_revoked_total {revoked}");

    // CA expiry
    let _ = writeln!(s, "# HELP vaultls_ca_expiry_timestamp_seconds CA certificate notAfter as unix seconds.");
    let _ = writeln!(s, "# TYPE vaultls_ca_expiry_timestamp_seconds gauge");
    for c in cas {
        let _ = writeln!(
            s,
            "vaultls_ca_expiry_timestamp_seconds{{id=\"{}\",cn=\"{}\",type=\"{}\"}} {}",
            c.id, escape_label_value(&c.cn), c.ca_type, c.expiry_seconds
        );
    }

    // ACME order problems (non-valid only)
    let _ = writeln!(s, "# HELP vaultls_acme_order_created_timestamp_seconds Creation time of in-flight/failed ACME orders as unix seconds.");
    let _ = writeln!(s, "# TYPE vaultls_acme_order_created_timestamp_seconds gauge");
    for o in orders.iter().filter(|o| o.status != "valid") {
        let _ = writeln!(
            s,
            "vaultls_acme_order_created_timestamp_seconds{{id=\"{}\",domain=\"{}\",status=\"{}\"}} {}",
            o.id, escape_label_value(&o.domain), escape_label_value(&o.status), o.created_seconds
        );
    }

    // acme_orders_total{status}
    let mut by_status: BTreeMap<String, i64> = BTreeMap::new();
    for o in orders {
        *by_status.entry(o.status.clone()).or_insert(0) += 1;
    }
    let _ = writeln!(s, "# HELP vaultls_acme_orders_total ACME client orders by status.");
    let _ = writeln!(s, "# TYPE vaultls_acme_orders_total gauge");
    for (st, n) in &by_status {
        let _ = writeln!(s, "vaultls_acme_orders_total{{status=\"{}\"}} {n}", escape_label_value(st));
    }

    s
}
```

- [ ] **Step 4: Add the `now_seconds` helper if missing**

The renderer uses `crate::helper::now_seconds()`. Check `backend/src/helper.rs`: if no such fn exists, add:

```rust
pub(crate) fn now_seconds() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}
```

- [ ] **Step 5: Register the module**

In `backend/src/lib.rs`, add `mod metrics;` next to the other `mod` declarations (near `mod api;`).

- [ ] **Step 6: Run tests + build**

Run: `cd backend && cargo test --lib metrics:: 2>&1 | tail -8 && cargo build 2>&1 | tail -5`
Expected: 3 tests PASS; build `Finished` zero warnings.

- [ ] **Step 7: Commit**

```bash
git add backend/src/metrics.rs backend/src/lib.rs backend/src/helper.rs
git commit -m "feat(metrics): pure Prometheus exposition renderer with label escaping

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: MetricsAuth guard (optional bearer token)

**Files:**
- Modify: `backend/src/metrics.rs` (add `check_metrics_token` + `MetricsAuth` guard + tests)

**Interfaces:**
- Produces:
  - `fn check_metrics_token(configured: Option<&str>, auth_header: Option<&str>) -> bool` — pure: `true` (allow) when `configured` is None/empty; otherwise `true` only if `auth_header == Some("Bearer <configured>")`.
  - `pub(crate) struct MetricsAuth;` implementing `rocket::request::FromRequest` — reads `VAULTLS_METRICS_TOKEN`, calls `check_metrics_token`, `Success(MetricsAuth)` or `Error((Status::Unauthorized, ()))`.

- [ ] **Step 1: Write the failing test**

Add to the `#[cfg(test)] mod tests` block in `backend/src/metrics.rs`:

```rust
    #[test]
    fn token_check_logic() {
        // unset/empty → always allow
        assert!(check_metrics_token(None, None));
        assert!(check_metrics_token(Some(""), Some("anything")));
        // set → require exact bearer
        assert!(check_metrics_token(Some("secret"), Some("Bearer secret")));
        assert!(!check_metrics_token(Some("secret"), Some("Bearer wrong")));
        assert!(!check_metrics_token(Some("secret"), None));
        assert!(!check_metrics_token(Some("secret"), Some("secret"))); // missing "Bearer "
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd backend && cargo test --lib metrics::tests::token_check_logic 2>&1 | tail -10`
Expected: FAIL — `cannot find function check_metrics_token`.

- [ ] **Step 3: Implement the pure check + guard**

Add to `backend/src/metrics.rs` (above the test module):

```rust
use rocket::request::{FromRequest, Outcome, Request};
use rocket::http::Status;

/// Pure token gate. `configured` = trimmed env value (None or empty = open).
fn check_metrics_token(configured: Option<&str>, auth_header: Option<&str>) -> bool {
    match configured {
        None => true,
        Some(t) if t.is_empty() => true,
        Some(t) => auth_header
            .and_then(|h| h.strip_prefix("Bearer "))
            .map(|got| got == t)
            .unwrap_or(false),
    }
}

pub(crate) struct MetricsAuth;

#[rocket::async_trait]
impl<'r> FromRequest<'r> for MetricsAuth {
    type Error = ();

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let configured = std::env::var("VAULTLS_METRICS_TOKEN").ok();
        let configured_trimmed = configured.as_deref().map(str::trim);
        let header = req.headers().get_one("Authorization");
        if check_metrics_token(configured_trimmed, header) {
            Outcome::Success(MetricsAuth)
        } else {
            Outcome::Error((Status::Unauthorized, ()))
        }
    }
}
```

- [ ] **Step 4: Run test + build**

Run: `cd backend && cargo test --lib metrics::tests::token_check_logic 2>&1 | tail -5 && cargo build 2>&1 | tail -5`
Expected: PASS; build zero warnings. (A `dead_code` warning on `MetricsAuth`/struct is expected ONLY until Task 3 uses it — if it appears, proceed; Task 3 consumes it. If you prefer zero warnings at this commit, that is acceptable to leave since the very next task wires it; do NOT add `#[allow(dead_code)]`.)

Note: if the build errors because `#[rocket::async_trait]` isn't the right attribute in this codebase, check how `session_auth.rs` declares `impl FromRequest` (it uses the same Rocket version) and match it.

- [ ] **Step 5: Commit**

```bash
git add backend/src/metrics.rs
git commit -m "feat(metrics): optional bearer-token guard for /metrics

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: /metrics route — DB gather + mount + integration test

**Files:**
- Modify: `backend/src/metrics.rs` (add the route handler + a gather helper)
- Modify: `backend/src/lib.rs` (mount in both rocket builds)

**Interfaces:**
- Consumes: `render_metrics`, `CertMetric`, `CaMetric`, `AcmeOrderMetric`, `MetricsAuth` (this file); `state.db.get_user_certs(None,None,None)`, `state.db.get_all_ca()`, `state.db.get_all_acme_client_orders()`, `state.db.get_all_acme_client_providers()`; `crate::constants::VAULTLS_VERSION`.
- Produces: `#[get("/metrics")] pub(crate) async fn metrics(...) -> ...`

- [ ] **Step 1: Implement the route + gather**

Add to `backend/src/metrics.rs`:

```rust
use rocket::{get, State};
use rocket::http::ContentType;
use crate::data::objects::AppState;
use crate::data::enums::{CertificateType, CAType};

fn cert_type_str(t: CertificateType) -> &'static str {
    match t {
        CertificateType::TLSClient => "tls_client",
        CertificateType::TLSServer => "tls_server",
        CertificateType::SSHClient => "ssh_client",
        CertificateType::SSHServer => "ssh_server",
    }
}

fn ca_type_str(t: CAType) -> &'static str {
    match t {
        CAType::TLS => "tls",
        CAType::SSH => "ssh",
    }
}

#[get("/metrics")]
pub(crate) async fn metrics(state: &State<AppState>, _auth: MetricsAuth) -> Result<(ContentType, String), rocket::http::Status> {
    let certs_db = state.db.get_user_certs(None, None, None).await
        .map_err(|_| rocket::http::Status::InternalServerError)?;
    let cas_db = state.db.get_all_ca().await
        .map_err(|_| rocket::http::Status::InternalServerError)?;
    let orders_db = state.db.get_all_acme_client_orders().await
        .map_err(|_| rocket::http::Status::InternalServerError)?;
    let providers = state.db.get_all_acme_client_providers().await
        .map_err(|_| rocket::http::Status::InternalServerError)?;

    // issuer lookups
    let provider_name = |pid: i64| providers.iter().find(|p| p.id == pid).map(|p| p.name.clone());
    let ca_cn = |cid: i64| cas_db.iter().find(|c| c.id == cid).map(|c| c.name.cn.clone());

    let certs: Vec<CertMetric> = certs_db.iter().map(|c| {
        let issuer = if let Some(pid) = c.acme_provider_id {
            format!("acme:{}", provider_name(pid).unwrap_or_else(|| pid.to_string()))
        } else if let Some(cid) = c.ca_id {
            format!("ca:{}", ca_cn(cid).unwrap_or_else(|| cid.to_string()))
        } else {
            "imported".to_string()
        };
        CertMetric {
            id: c.id,
            cn: c.name.cn.clone(),
            cert_type: cert_type_str(c.certificate_type),
            issuer,
            expiry_seconds: c.valid_until / 1000,
            revoked: c.revoked_at.is_some(),
        }
    }).collect();

    let cas: Vec<CaMetric> = cas_db.iter().map(|c| CaMetric {
        id: c.id,
        cn: c.name.cn.clone(),
        ca_type: ca_type_str(c.ca_type),
        expiry_seconds: c.valid_until / 1000,
    }).collect();

    let orders: Vec<AcmeOrderMetric> = orders_db.iter().map(|o| AcmeOrderMetric {
        id: o.id,
        domain: o.domain.clone(),
        status: o.status.clone(),
        created_seconds: o.created_on / 1000,
    }).collect();

    let body = render_metrics(crate::constants::VAULTLS_VERSION, &certs, &cas, &orders);
    Ok((ContentType::new("text", "plain").with_params(("version", "0.0.4")), body))
}
```

(Confirm the field name for the leaf CA link is `ca_id` and revocation is `revoked_at` on `Certificate` — both exist per `certs/common.rs`. Confirm `CertificateType`/`CAType` are `Copy`; if not, use a reference match or `.clone()`.)

- [ ] **Step 2: Mount the route in both rocket builds**

In `backend/src/lib.rs`:
- In `create_rocket()` (the production builder ending with `.attach(AdHoc::config::<Settings>())` around line 258), add `.mount("/", rocket::routes![crate::metrics::metrics])` to the builder chain (e.g. right before `.attach(AdHoc::config::<Settings>())`).
- In `create_test_rocket()`, add the same `.mount("/", rocket::routes![crate::metrics::metrics])` to its builder chain.

(If `routes!` is already imported in `lib.rs`, use `routes![crate::metrics::metrics]`; otherwise use the fully-qualified `rocket::routes!`.)

- [ ] **Step 3: Write the integration test**

Add to `backend/src/metrics.rs` test module (uses the test rocket + Rocket's local async client):

```rust
    #[tokio::test]
    async fn metrics_endpoint_serves_exposition() {
        // No VAULTLS_METRICS_TOKEN set in test → open endpoint.
        let rocket = crate::create_test_rocket().await;
        let client = rocket::local::asynchronous::Client::tracked(rocket).await.unwrap();
        let resp = client.get("/metrics").dispatch().await;
        assert_eq!(resp.status(), rocket::http::Status::Ok);
        let body = resp.into_string().await.unwrap();
        assert!(body.contains("vaultls_build_info"));
        assert!(body.contains("# TYPE vaultls_certificates_total gauge"));
    }
```

If `create_test_rocket` is not `pub` / not reachable from the module, make it `pub(crate)` in `lib.rs` (it is defined there). Rocket's `local` module is available with the default features already used by this crate.

- [ ] **Step 4: Build + tests**

Run: `cd backend && cargo build 2>&1 | tail -8 && cargo test --lib metrics 2>&1 | tail -8`
Expected: build `Finished`, ZERO warnings (MetricsAuth now consumed); all metrics tests PASS incl. `metrics_endpoint_serves_exposition`.

- [ ] **Step 5: Commit**

```bash
git add backend/src/metrics.rs backend/src/lib.rs
git commit -m "feat(metrics): /metrics route gathering certs, CAs and ACME orders from DB

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: Observability documentation

**Files:**
- Create: `docs/observability.md`

**Interfaces:** none (docs only).

- [ ] **Step 1: Write the doc**

Create `docs/observability.md` with these sections (fill the metric table from the metric names/labels in Global Constraints, and use these exact examples):

Metrics table (name | type | labels | meaning) covering all eight metrics.

Prometheus scrape config:
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

Alert rules:
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

Alertmanager route/receiver example:
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

Add a security note: if `VAULTLS_METRICS_TOKEN` is unset, `/metrics` is unauthenticated — restrict it with a NetworkPolicy / firewall, or set the token.

- [ ] **Step 2: Commit**

```bash
git add docs/observability.md
git commit -m "docs(metrics): observability guide with Prometheus + Alertmanager examples

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: Helm — metrics token + scrape annotations

**Files:**
- Modify: `helm-chart/values.yaml`
- Modify: `helm-chart/templates/deployment.yaml`

**Interfaces:** none (chart).

- [ ] **Step 1: values.yaml — add a metrics block**

In `helm-chart/values.yaml`, under `config:` add:

```yaml
  metrics:
    # -- Bearer token for /metrics (VAULTLS_METRICS_TOKEN). Empty = endpoint is unauthenticated.
    token: ""
    # -- Pod annotations for Prometheus scraping (set enabled=false to omit).
    scrapeAnnotations:
      enabled: true
```

- [ ] **Step 2: deployment.yaml — env passthrough**

In `helm-chart/templates/deployment.yaml`, in the container `env:` list (next to the other `{{- if .Values.config.acme.* }}` blocks), add:

```yaml
            {{- if .Values.config.metrics.token }}
            - name: VAULTLS_METRICS_TOKEN
              value: {{ .Values.config.metrics.token | quote }}
            {{- end }}
```

- [ ] **Step 3: deployment.yaml — pod scrape annotations**

In `helm-chart/templates/deployment.yaml`, the pod template already has an `annotations:` block (around line 19). Append, guarded by the toggle, the Prometheus annotations (use the container/service port used by the app — reference the existing port value the chart already uses for the container, e.g. `.Values.service.port` or the containerPort; match whatever the chart already references elsewhere):

```yaml
        {{- if .Values.config.metrics.scrapeAnnotations.enabled }}
        prometheus.io/scrape: "true"
        prometheus.io/path: "/metrics"
        prometheus.io/port: {{ .Values.service.port | quote }}
        {{- end }}
```

(Confirm the correct existing port value key in this chart — reuse it rather than hardcoding.)

- [ ] **Step 4: Render to verify**

Run from `helm-chart/`:
```bash
helm template t . --set secrets.apiSecret=$(openssl rand -base64 32) --set config.metrics.token=abc 2>&1 | grep -A1 "VAULTLS_METRICS_TOKEN"
helm template t . --set secrets.apiSecret=$(openssl rand -base64 32) 2>&1 | grep "prometheus.io/scrape"
```
Expected: first shows the env var with value `"abc"`; second shows `prometheus.io/scrape: "true"`.

- [ ] **Step 5: Commit**

```bash
git add helm-chart/values.yaml helm-chart/templates/deployment.yaml
git commit -m "feat(metrics): Helm passthrough for VAULTLS_METRICS_TOKEN + scrape annotations

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Manual verification (after all tasks)

1. `cd backend && cargo build && cargo test --lib metrics` → zero warnings, green.
2. Run the app; `curl -s localhost:<port>/metrics | head -40` → exposition with `vaultls_build_info`, cert/CA expiry lines, aggregates.
3. With `VAULTLS_METRICS_TOKEN=secret`: `curl -so /dev/null -w "%{http_code}" localhost:<port>/metrics` → `401`; with `-H "Authorization: Bearer secret"` → `200`.
4. `promtool check rules` on the alert-rules snippet → SUCCESS.
5. `helm template` renders token env + scrape annotations.

## Notes on scope / compatibility

- Additive: new module + route + docs + chart values; existing routes untouched.
- No new heavy dependency; formatter is hand-rolled and unit-tested.
- Per-scrape DB reads are a handful of SELECTs — negligible at 60s intervals.
