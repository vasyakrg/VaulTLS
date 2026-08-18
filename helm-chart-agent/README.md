# vaultls-agent (Helm chart)

Runs [vaultls-agent](../api-client/README.md) in a cluster and keeps one
`kubernetes.io/tls` Secret per configured certificate up to date. Replicating
those Secrets into other namespaces is left to Kyverno (or any equivalent), see
[below](#replicating-to-other-namespaces).

The agent runs as a Deployment rather than a CronJob: it already carries a cron
scheduler with jitter and a Prometheus exporter, and a live pod is what makes
`vaultls_cert_expiry_timestamp_seconds` scrapeable — a CronJob's metrics vanish
with the pod.

## Install

```bash
helm upgrade --install vaultls-agent ./helm-chart-agent \
  --namespace vaultls --create-namespace \
  --set vaultls.url=https://vaultls.example.com \
  --set vaultls.clientId=svc_xxxxxxxx \
  --set vaultls.secret=YOUR_SECRET
```

The credentials are rendered into a Secret and reach the agent through
`VAULTLS_CLIENT_ID` / `VAULTLS_SECRET`, which the config expands — they never
land in the ConfigMap. To manage the Secret yourself, create one with the keys
`client_id` and `secret` and set `vaultls.existingSecret` to its name.

## Values

| Key | Default | Description |
|---|---|---|
| `image.repository` | `ghcr.io/vasyakrg/vaultls-agent` | Image (linux/amd64). |
| `image.tag` | `""` | Defaults to `.Chart.AppVersion`. |
| `vaultls.url` | — | VaulTLS server URL. Required. |
| `vaultls.clientId` / `vaultls.secret` | — | Service account credentials (`cert:read`). Required unless `existingSecret` is set. |
| `vaultls.existingSecret` | `""` | Use an existing Secret with keys `client_id` and `secret`. |
| `vaultls.insecureSkipVerify` | `false` | Skip TLS verification of the VaulTLS server. |
| `schedule` | `"0 3 * * *"` | Cron expression for the reconcile loop. |
| `jitter` | `30m` | Random delay added to each scheduled run. |
| `certificates[].name` | — | Certificate name in VaulTLS, e.g. `"*.example.com"`. |
| `certificates[].certId` | — | Pin an exact certificate id instead of matching by name. |
| `certificates[].namespace` | `default` | Namespace of the managed Secret. |
| `certificates[].secretName` | — | Name of the managed Secret. |
| `certificates[].includeCA` | `true` | Also write the chain as `ca.crt`. |
| `certificates[].labels` | `vaultls.io/replicate: "true"` | Extra labels on the Secret — what the replication policy selects on. |
| `rbac.create` | `true` | Render a Role/RoleBinding per target namespace. |
| `metrics.serviceMonitor.enabled` | `false` | Render a Prometheus Operator ServiceMonitor. |

## RBAC

One Role per target namespace, never a ClusterRole. `create` cannot be narrowed
by `resourceNames` (the object does not exist yet when the request is
authorized), so it is a separate rule; `get`/`update`/`patch` are pinned to the
exact Secret names from `certificates[]`.

## Replicating to other namespaces

The agent deliberately writes **one** Secret per certificate. Fanning it out is
a job for policy tooling, which handles namespace lifecycle and drift better
than a certificate agent would.

**1. Let Kyverno touch Secrets.** Without these ClusterRoles the background
controller silently fails to clone — it has no access to Secrets by default:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: kyverno:secrets:view
  labels:
    rbac.kyverno.io/aggregate-to-background-controller: "true"
    rbac.kyverno.io/aggregate-to-admission-controller: "true"
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: kyverno:secrets:manage
  labels:
    rbac.kyverno.io/aggregate-to-background-controller: "true"
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["create", "update", "delete"]
```

**2. Clone the labelled Secrets into labelled namespaces.**

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: sync-vaultls-certs
spec:
  rules:
    - name: clone-certs
      match:
        any:
          - resources:
              kinds: [Namespace]
              selector:
                matchLabels:
                  vaultls.io/certs: "true"
      exclude:
        any:
          - resources:
              namespaces: [kube-system, kube-public, kube-node-lease, default, kyverno]
      generate:
        namespace: "{{request.object.metadata.name}}"
        synchronize: true
        cloneList:
          namespace: default
          kinds: [v1/Secret]
          selector:
            matchLabels:
              vaultls.io/replicate: "true"
```

`synchronize: true` is what closes the loop: when the agent rotates the source
Secret, the background controller pushes the new material into every clone. No
extra trigger, no second agent.

Opt a namespace in with `kubectl label ns myapp vaultls.io/certs=true`.

## Two things that will bite you

1. **The clones inherit the `vaultls.io/*` state annotations.** Harmless — the
   agent only ever reads them from the source Secret — but do not mistake them
   for per-namespace state.
2. **Updating a Secret does not restart anything.** Ingress controllers re-read
   Secrets on their own; a Deployment that mounts one gets fresh files (kubelet
   sync, up to ~1 min) but the process inside keeps the old certificate in
   memory. Use [Reloader](https://github.com/stakater/Reloader) or roll the
   workloads.

## Verify

```bash
kubectl logs -n vaultls deploy/vaultls-agent
kubectl get secret -n default wildcard-example-com -o jsonpath='{.metadata.annotations}'
kubectl get secret -n default wildcard-example-com -o jsonpath='{.data.tls\.crt}' | base64 -d | openssl x509 -noout -dates -subject
```
