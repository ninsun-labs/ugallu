# ugallu-bff

Backend-for-Frontend that powers the ugallu UI. Reads from the
cluster's `security.ugallu.io/v1alpha1` group and exposes a small
REST surface to the SvelteKit SPA, gated by an OIDC-derived
session cookie.

The BFF holds the cluster ServiceAccount; the browser only ever
holds an HMAC-signed cookie carrying `sub` + `email` + `groups` +
`exp`. RBAC denies every verb other than `get`/`list`/`watch` on
the security.ugallu.io group, so the BFF cannot proxy mutations.

## Routes

| Path                    | Auth   | Purpose                                                     |
| ----------------------- | ------ | ----------------------------------------------------------- |
| `GET  /healthz`         | none   | Liveness                                                    |
| `GET  /readyz`          | none   | Readiness                                                   |
| `GET  /auth/login`      | none   | Start OIDC + PKCE redirect                                  |
| `GET  /auth/callback`   | none   | Exchange auth code, set session cookie                      |
| `POST /auth/logout`     | none   | Clear session cookie                                        |
| `GET  /api/v1/me`       | cookie | Current user payload                                        |
| `GET  /api/v1/events`   | cookie | List SecurityEvents (paged, filterable)                     |
| `GET  /api/v1/events/{name}` | cookie | Full SecurityEvent CR                                  |

OpenAPI spec: [`api/openapi.yaml`](api/openapi.yaml).

## Run

```bash
export OIDC_CLIENT_SECRET=<keycloak-client-secret>
export COOKIE_SECRET=$(openssl rand -hex 32)

go run . \
  -listen :8080 \
  -oidc-issuer https://keycloak.example.internal/realms/ugallu \
  -oidc-client-id ugallu-ui \
  -external-url https://ugallu.example.internal \
  -cookie-domain example.internal
```

In-cluster the binary uses the in-cluster K8s config; outside the
cluster it falls back to `~/.kube/config` via `controller-runtime`.

## Identity model

Two identities, one per request:

1. **Static cluster ServiceAccount** (`ugallu-ui-bff`) - the actual
   apiserver client. Read-only RBAC on `security.ugallu.io`.
2. **Per-request impersonation** (`Impersonate-User: <oidc-sub>`) -
   surfaces the human actor in the apiserver audit log even on
   read calls. Toggle with `--impersonate=false` to disable.

Audit log entries for an SE list look like:

```
user: system:serviceaccount:ugallu-system:ugallu-ui-bff
impersonatedUser: alice@example.internal
groups: [ugallu-viewer]
verb: list
objectRef: { resource: securityevents, ... }
```

## Cookie

Single signed cookie `ugallu_session`. Format:

```
base64url(json) + "." + base64url(hmac-sha256(secret, json))
```

The HMAC keeps the cookie integrity-protected; the body itself is
not encrypted because the contents (sub, email, groups, exp) are
not sensitive enough to justify the operational complexity of
rotating an encryption key. If you need encryption, swap in a
sealed-cookie library and rotate the key via the chart's
`cookieSecretRef`.

## What this does NOT cover (yet)

- **Write endpoints.** Acks, run triggers, configuration edits stay
  on `kubectl apply` / GitOps for v0.1.0-alpha.1.
- **Live tail.** No SSE / WebSocket stream of new SE - the SPA
  polls `/events`. Server-sent events land in a follow-up.
- **Per-tenant filtering.** RBAC at the apiserver constrains what
  the BFF can list; the BFF does not re-enforce based on OIDC
  groups. That belongs in admission policy + ClusterRoleBindings.

## Development

```bash
# inside cmd/ugallu-bff
go mod tidy
go vet ./...
go test ./...
```

The binary ships in the multi-binary `ugallu-runtime` image.
