# rbac

Least-privilege RBAC bundle for the 5 ugallu Wave 1 binaries (design 13). Closes review H2.

## Components

| SA | Namespace | Privilege summary |
|---|---|---|
| `ugallu-resolver` | `ugallu-system-privileged` | watch Pod/Node/SA/Ns/EndpointSlice (no writes); own Lease |
| `ugallu-attestor` | `ugallu-system` | watch SE/ER; full CRUD on AB; **only `/status` subresource** patch on SE/ER (no Spec); own AttestorConfig + TokenRequest for OIDC; own Lease |
| `ugallu-ttl` | `ugallu-system` | get/list/watch + delete on SE/ER/AB; **patch on SE/ER/AB restricted to `/metadata/annotations` by admission policy 3**; create SE for telemetry; watch ugallu pods (attestor watchdog); own Lease |
| `ugallu-audit-detection` | `ugallu-system` | **create only** on SE; get/list/watch own config CRD; own Lease |
| `ugallu-forensics` | `ugallu-system-privileged` | create SE/ER; CRUD IncidentResponse + status; pod/log read; pod/exec; pods/ephemeralcontainers; CiliumNetworkPolicy create/delete; own Lease |

## Hardening interplay

- **Admission policies (subchart `admission-policies`)** compensate for the few "wide" RBACs:
  - `ugallu-ttl` has `patch` on full CR but admission policy 3 restricts the patch surface to annotations
  - Operators with `/status` patch are restricted by admission policy 4 from setting `Acknowledged=true` unless explicitly allowlisted
- **Status/Spec separation**: NO component is granted UPDATE/PATCH on SE/ER (full CR). Updates flow through `/status` subresource only

## Override knobs

```yaml
rbac:
  resolver: { enabled: true }
  attestor: { enabled: true }
  ttl: { enabled: true }
  auditDetection: { enabled: true }
  forensics: { enabled: true }
  ciliumNetworkPolicies: true   # set false on non-Cilium clusters
```
