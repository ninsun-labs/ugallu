# argocd/

ArgoCD bootstrap manifests for the ugallu platform. Designed for the companion repository [`ninsun-labs/argocd`](https://github.com/ninsun-labs/argocd) to import this directory as a sub-app.

## Files

| File | Purpose |
|---|---|
| `appproject.yaml` | `AppProject` scoping permissions for the ugallu ApplicationSet |
| `applicationset.yaml` | `ApplicationSet` generating one Application per component, sync-wave-ordered (design 17) |

## Wave plan (active in this commit)

| Wave | Component | Path |
|---|---|---|
| -2 | `ugallu-namespaces` | `charts/ugallu/charts/namespaces` |
| -2 | `ugallu-rbac` | `charts/ugallu/charts/rbac` |
| -1 | `ugallu-crds` | `crds` (kustomize) |
| -1 | `ugallu-admission-policies` | `charts/ugallu/charts/admission-policies` |

## Wave plan (planned, commented in `applicationset.yaml`)

| Wave | Component | When |
|---|---|---|
| 0 | seaweedfs, openbao, spire | when external deps subcharts land |
| 1 | resolver, attestor, ttl | when SDK runtime singletons subcharts land |
| 2 | audit-detection, forensics | when Wave 1 operators are deployable |

## Bootstrap

In a cluster with ArgoCD installed:

```bash
kubectl apply -f argocd/appproject.yaml
kubectl apply -f argocd/applicationset.yaml
```

ArgoCD discovers the four entries in the ApplicationSet generator, creates one Application each, and syncs them in wave order.

`ServerSideApply=true` is required because the `SecurityEvent` CRD is ~470 KB (full Subject discriminator inlined) and exceeds the client-side apply size limit.

## Verification

```bash
argocd app list -p ugallu
argocd app sync -p ugallu  # initial sync of all generated Applications
ugallu doctor              # cluster preflight (when CLI lands)
```

## Tightening (post-1.0)

The `AppProject` currently allows any `clusterResourceWhitelist` and `namespaceResourceWhitelist`. Once the platform's resource catalogue is stable, restrict these to the exact Kinds ugallu deploys.
