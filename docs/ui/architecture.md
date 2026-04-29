# Ugallu UI — architecture decisions (Wave 5 §S2)

**Status:** approved 2026-04-29 by repository owner.
**Implementation sprint:** Wave 5 §S5–§S8.

## 1. Stack

| Layer | Choice | Rationale |
|---|---|---|
| Frontend | **SvelteKit + TypeScript + ShadCN-Svelte** | Smallest runtime + bundle, SSR-fast, modern DX. ShadCN-Svelte parity with the React port covers every component the SOC view needs. |
| Backend-for-Frontend (BFF) | **Go HTTP server (`cmd/ugallu-bff`)** | Reuses the SDK emitter/resolver pattern. Keeps K8s service-account tokens out of the browser; the browser sees only short-lived signed cookies. |
| Auth | **OIDC (Keycloak) — Authorization Code + PKCE** | The lab already runs Keycloak. PKCE means no client secret in the SPA; the BFF holds the secret and validates the JWT. |
| Hosting | **Umbrella subchart `charts/ugallu/charts/ugallu-ui`** | One `helm install` ships the whole platform. Spin-out into a dedicated repo is a Wave 6+ decision once contributor flow stabilises. |
| Routing into the cluster | Ingress with cert-manager (existing) — `ui.ugallu.local` (lab) / `ugallu.<domain>` (prod) | No cluster-LB churn. |

## 2. Architecture diagram

```
+----------------+      OIDC        +-------------+
|  Browser (SPA) | <--------------> |  Keycloak   |
|  SvelteKit     |   Auth Code +    +-------------+
|  ShadCN-Svelte |   PKCE
+--------+-------+
         |
         | HTTPS, signed session cookie
         v
+----------------+   K8s SA token   +-----------+
|  ugallu-bff    | ---------------> | apiserver |
|  Go HTTP       |  impersonation:  +-----------+
|  + emitter SDK |  ugallu-ui-viewer
+----------------+
```

The BFF holds **two identities**:
- A static cluster ServiceAccount `ugallu-ui-bff` (full read on the
  ugallu CRDs the dashboard queries).
- A per-request impersonation header `Impersonate-User` set from the
  OIDC subject so apiserver audit retains the human actor — even for
  read-only ops. RBAC denies any verb other than get/list/watch on
  the security.ugallu.io group; the BFF never proxies writes.

## 3. Entity model surfaced in the UI

Every entity below is a CRD already present in the SDK. The UI
doesn't introduce new types in v0.1.0-alpha.1 — the BFF is a
translation layer over the existing `security.ugallu.io/v1alpha1`
group plus a small derivation.

```
SecurityEvent (the headline entity)
  ├── SubjectTier1 (Pod / Node / Namespace / …)
  ├── Class + Type + Severity + CorrelationID
  └── AttestationBundleRef (when sealed)

Run/Result family (one row per run + per result)
  ├── BackupVerifyRun     → BackupVerifyResult
  ├── ComplianceScanRun   → ComplianceScanResult
  ├── ConfidentialAttestationRun → ConfidentialAttestationResult
  └── SeccompTrainingRun  → SeccompTrainingProfile

Config singletons (shown as "Configuration" panes)
  ├── AuditDetectionConfig / DNSDetectConfig / …
  ├── ForensicsConfig
  └── HoneypotConfig

Derived (BFF-only, computed):
  ├── IncidentTimeline   = SE list grouped by CorrelationID
  └── ClusterPosture     = aggregate compliance pass/fail counts
```

## 4. View hierarchy (v0.1.0-alpha.1)

```
/ (Dashboard)            → cluster posture + last 24h SE roll-up
/events                  → SecurityEvent list (filters: class, type, severity, namespace)
/events/<name>           → SE detail (signals, subject, attestation status, related SE via CorrelationID)
/runs                    → unified Run list across the 4 Run kinds
/runs/<kind>/<name>      → Run detail + linked Result
/configurations          → AuditDetection / DNSDetect / Forensics / Honeypot CRs
/honeypots               → HoneypotConfig CR + decoy inventory
/audit                   → recent EventResponse log (cluster-wide) + AttestationBundle status
```

Out of v0.1.0-alpha.1 (Wave 6+ candidates):
- **Incident graph** — correlation-id based SE network map (Hubble-style). Adds the "graph" route + a new SVG/d3 dep.
- **Live tail** — server-sent events stream of new SE. Needs an SSE endpoint on the BFF.
- **Bulk ack** — write path through the BFF (currently read-only).

## 5. BFF API surface (v0.1.0-alpha.1)

REST under `/api/v1/`. JSON only. Every response carries a
`generation` field (the K8s `resourceVersion` of the underlying CR)
so SvelteKit can skip rerender on equal-generation polls.

```
GET  /api/v1/me                          OIDC subject + RBAC summary
GET  /api/v1/events                      SE list (paged, filterable)
GET  /api/v1/events/:name                SE detail
GET  /api/v1/events?correlationID=…      SE in the same incident
GET  /api/v1/runs                        unified run list (4 kinds joined)
GET  /api/v1/runs/:kind/:ns/:name        run detail + result
GET  /api/v1/configurations              all *Config CR singletons
GET  /api/v1/honeypots                   HoneypotConfig + decoy list
GET  /api/v1/posture                     compliance pass/fail roll-up
```

No write endpoints in v0.1.0-alpha.1; mutations stay on `kubectl
apply` / GitOps. Write flows (Ack incident, trigger run) are tracked
for Wave 6.

## 6. Auth flow (Authorization Code + PKCE)

```
1. Browser → /             (no cookie)
2. SPA calls GET /api/v1/me
3. BFF sees no cookie → returns 401 with a redirect URL (RFC 8252
   recommended PKCE flow):
     code_verifier = random 43-128 chars
     code_challenge = base64url(sha256(code_verifier))
     redirect → keycloak/authorize?code_challenge=…&...
4. Keycloak prompts user, returns auth code to /auth/callback
5. BFF exchanges code+code_verifier for id_token at the token
   endpoint, validates signature against Keycloak JWKS, sets a
   secure http-only cookie carrying:
     - sub
     - groups
     - exp
     - csrf_token (for write endpoints in Wave 6)
6. SPA retries GET /api/v1/me → 200 + user payload
```

Secret material on the BFF is mounted from a Secret created by the
chart. The OIDC issuer URL + client_id are configurable; client
secret is mounted from a separate Secret.

## 7. Subchart sketch (`charts/ugallu/charts/ugallu-ui`)

```
charts/ugallu/charts/ugallu-ui/
├── Chart.yaml
├── values.yaml
└── templates/
    ├── _helpers.tpl
    ├── 01-rbac.yaml          ServiceAccount + ClusterRole (read-only)
    ├── 02-deployment.yaml    BFF + nginx-frontend (single Pod, two
    │                          containers)
    ├── 03-service.yaml       ClusterIP :8080 (BFF) + :80 (frontend)
    ├── 04-ingress.yaml       cert-manager-issued cert
    └── 05-oidc-config.yaml   ConfigMap with issuer + client_id
```

Both the BFF binary and the static frontend assets ship in the same
`localhost/ugallu-runtime:waveN-rcN` multi-binary image — keeps the
existing build pipeline green. The frontend serves out of an
nginx-distroless sidecar reading `/srv/www/ugallu-ui/`.

## 8. Sprint plan for the UI implementation (S5–S8)

| Sprint | Output |
|---|---|
| **S5** | BFF skeleton: `cmd/ugallu-bff` + `pkg/bff/server` (auth middleware, /api/v1/me, /api/v1/events list+get, OpenAPI spec emitted). |
| **S6** | SPA skeleton: SvelteKit init, Tailwind + ShadCN-Svelte, layout shell, /events list view live. Auth wired against the BFF cookie. |
| **S7** | Run management views (S5 BFF endpoints + S6 list/detail). Configuration view (read-only YAML pane). |
| **S8** | Subchart + cert-manager wiring + Helm values + lab smoke E2E (BFF healthz + UI loads + SE list returns >= 1). |
