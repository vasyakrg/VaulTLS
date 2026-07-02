# ACME Client (Let's Encrypt & compatible CAs)

Besides acting as an ACME **server** (see [`acme.md`](acme.md)), VaulTLS can act as an
ACME **client**: it obtains **public** TLS certificates from Let's Encrypt and any
RFC 8555-compatible CA (ZeroSSL, BuyPass, …) using the **dns-01** challenge.

Issued certificates are stored alongside your other certificates and shown in the
**Overview** tab (the *CA Name* column shows the provider name instead of an internal CA).
You download them from Overview and install them on your services yourself — VaulTLS is
the store & distribution point, not the TLS terminator.

> **Server vs. client — don't confuse them.** The **ACME** tab makes VaulTLS a CA that
> *signs* certificates for clients like Traefik/acme.sh. The **Let's Encrypt** tab makes
> VaulTLS a client that *obtains* certificates from public CAs. They are independent
> subsystems.

## Semi-automatic dns-01 flow

DNS is not automated (no RFC 2136 / DNS-provider API), so issuance is a **two-phase,
semi-manual** process:

1. **Create order** — pick a provider, enter the base domain, optionally tick *wildcard*
   (`example.com` + `*.example.com`). VaulTLS creates the ACME order and shows you the
   `_acme-challenge.<domain>` **TXT record(s)** to publish. For a wildcard order you get
   two TXT records with the same name and different values.
2. Publish the TXT records in your DNS zone (e.g. bind9: add records, bump the serial,
   `rndc reload`) and wait for propagation.
3. **Check DNS** — VaulTLS queries the resolver (no ACME contact yet, to protect the CA
   rate limit) and confirms the expected TXT values are visible.
4. **Start issuance** — only enabled once the DNS check passes. VaulTLS finalizes the
   order, fetches the certificate and stores it. It now appears in Overview for download.

Wildcard identifiers require dns-01 (an ACME protocol rule) — that is why VaulTLS only
supports dns-01 for the client, and http-01 is not offered.

## Providers

The **Let's Encrypt** tab has a *Providers* section. Two presets are seeded on first run:

| Preset | Directory URL |
|--------|---------------|
| Let's Encrypt (production) | `https://acme-v02.api.letsencrypt.org/directory` |
| Let's Encrypt (staging) | `https://acme-staging-v02.api.letsencrypt.org/directory` |

Use **staging** while testing DNS wiring — it has far looser rate limits and issues
untrusted certs, so you don't burn production quota on failed attempts.

Add other CAs by entering a name, directory URL and contact email. CAs that require
**External Account Binding** (ZeroSSL, BuyPass) also take an EAB Key ID and HMAC key.
The ACME account is registered lazily on the first order and reused afterwards.

## Renewal

Renewal is **certbot-like**: a new key each time, a **30-day** pre-expiry window, and
**opt-in** per certificate via its renew method:

- **Renew** — the background notifier attempts renewal automatically.
- **Renew & notify** — same, plus an email.
- (no renew method) — never auto-renewed.

How auto-renewal behaves depends on the ACME authorization state:

- **Authorization still valid** (the CA reused it, typically for ~30 days) — no TXT is
  needed; VaulTLS renews **in place** (same certificate ID) fully unattended.
- **Authorization expired** — VaulTLS creates a new order, leaves it `pending_dns`, and
  emails you the TXT records to publish. You then hit **Check DNS → Start issuance** and
  the certificate is updated in place.

You can also renew manually with the **Renew** button on an issued certificate — it
reuses a valid authorization when possible and always updates the existing certificate
in place (no duplicate rows).

## DNS resolver

The DNS check uses the same resolver as the ACME server. Override it with
`VAULTLS_ACME_DNS_RESOLVER` (plain IP, `tls://` for DNS-over-TLS, or `https://` for
DNS-over-HTTPS) — see the *DNS Challenge Resolver* section in [`acme.md`](acme.md).
This is useful when `_acme-challenge` records live on internal DNS.

## Troubleshooting

- **Order rejected right after *Start issuance*** — the error message distinguishes a
  **CAA policy** failure (a `CAA` record forbids the chosen CA from issuing for the
  domain) from a TXT-propagation problem, so you don't waste time re-checking TXT when
  the real blocker is CAA. Fix the domain's CAA records and retry.
- **TXT not visible yet** — the *Check DNS* gate keeps the order in `pending_dns` and
  reports the missing values without contacting the CA. Wait for propagation and retry.
- **Order expired (~7 days)** — recreate it; Let's Encrypt issues fresh TXT values on
  each new order.
