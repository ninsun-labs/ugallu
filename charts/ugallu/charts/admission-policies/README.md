# admission-policies

ValidatingAdmissionPolicy (CEL native, K8s >= 1.30) rules enforcing the security invariants of the `security.ugallu.io/v1alpha1` API group.

Deployed at sync-wave `-1` of the umbrella chart so the policies are active before any ugallu CR can be created.

## Policies

| # | Name | Scope | Purpose |
|---|---|---|---|
| 1 | `ugallu.spec-immutable` | UPDATE on SE/ER/AB | reject any change to `Spec` |
| 2 | `ugallu.subject-discriminator` | CREATE on SE | enforce `Subject.Kind` matches the populated discriminator |
| 3 | `ugallu.ttl-annotation-only` | UPDATE by `ugallu-ttl` SA on SE/ER/AB | restrict the TTL controller to `metadata.annotations` patches |
| 4 | `ugallu.ack-restricted` | UPDATE on SE/ER `/status` subresource | only authorized SAs can set `Status.Acknowledged=true` |
| 5 | `ugallu.type-validation` | CREATE on SE | reject `spec.type` not in the curated catalog (override via label `ugallu.io/type-experimental=true`) |

All policies use `failurePolicy: Fail` and `validationActions: [Deny]`: API server rejects requests that fail validation.

## Drift management

Policy 5 inlines the curated `Type` catalog. When `sdk/pkg/api/v1alpha1/types.go` is updated, the inline list in `templates/05-type-validation.yaml` must be updated too. A future CI job will assert parity automatically.

## Override knobs (subchart values)

```yaml
admission-policies:
  enabled: true
  ackAuthorizedSAs:
    - system:serviceaccount:ugallu-system:my-ack-bot
  ttlControllerNamespace: ugallu-system
  ttlControllerSAName: ugallu-ttl
```
