# dev-stack

Bring up a SeaweedFS (S3 + Object Lock) and Rekor (Trillian + MySQL +
Redis) stack inside a kind cluster for end-to-end smoke testing of the
ugallu attestor pipeline. **Not for production**: emptyDir storage,
static credentials, single-replica components.

## Prerequisites

- A running kind cluster pointed at by your current `kubectl` context
- ugallu CRDs and admission policies already applied
- Internet egress (the scripts pull `mysql:8.0`, `redis:7-alpine`,
  the Trillian + Rekor + SeaweedFS images, and fetch the live
  Trillian MySQL schema from the upstream repo)

## Bring up / tear down

```bash
bash hack/dev-stack/up.sh    # idempotent
bash hack/dev-stack/down.sh
```

`up.sh` creates the namespace `ugallu-evidence`, waits for everything
to become ready, runs the `createtree` Job that writes Trillian's
generated treeID into the `rekor-config` ConfigMap, restarts
`rekor-server` so it picks the treeID up, and creates the `ugallu` S3
bucket with Object Lock enabled.

## Plugging the attestor in

The attestor binary speaks both backends with the flags below
(matching what `up.sh` provisions):

```
--rekor-url=http://rekor-server.ugallu-evidence.svc.cluster.local:3000
--worm-backend=s3
--worm-s3-endpoint=http://seaweedfs.ugallu-evidence.svc.cluster.local:8333
--worm-s3-bucket=ugallu
--worm-s3-path-style=true
--worm-s3-key-prefix=attestations
--worm-s3-lock-mode=COMPLIANCE
--worm-s3-access-key=ugallu-access
--worm-s3-secret-key=ugallu-secret
--worm-retention=168h
```

After redeploying the attestor with these args, create a test
`SecurityEvent` and watch its `AttestationBundle` reach `Phase=Sealed`
with both `RekorEntry` and `WormRef` populated.

## Components

| Service                  | Image                                              | Purpose                              |
|--------------------------|----------------------------------------------------|--------------------------------------|
| seaweedfs                | `chrislusf/seaweedfs:3.97`                         | S3 API + Object Lock storage         |
| trillian-mysql           | `mysql:8.0`                                        | backing store for Trillian           |
| trillian-log-server      | `gcr.io/trillian-opensource-ci/log_server:latest`  | append-only log gRPC service         |
| trillian-log-signer      | `gcr.io/trillian-opensource-ci/log_signer:latest`  | log STH signer                       |
| redis                    | `redis:7-alpine`                                   | Rekor search index                   |
| rekor-server             | `gcr.io/projectsigstore/rekor-server:v1.4.2`       | Sigstore Rekor v1 transparency log   |
| createtree (Job)         | `ghcr.io/sigstore/scaffolding/createtree:v0.7.18`  | bootstrap a Trillian tree            |
| aws-cli (pod)            | `amazon/aws-cli:2.27.50`                           | bucket admin + interactive S3 ops    |

## Inspecting state

```bash
# Pods
kubectl -n ugallu-evidence get pods

# Rekor tree size + root hash
kubectl -n ugallu-evidence exec aws-cli -- sh -c 'curl -s http://rekor-server:3000/api/v1/log'

# List archived envelopes
kubectl -n ugallu-evidence exec aws-cli -- \
  aws s3 ls s3://ugallu/attestations/ --recursive \
    --endpoint-url=http://seaweedfs:8333

# Verify Object Lock retention on a specific object
kubectl -n ugallu-evidence exec aws-cli -- \
  aws s3api get-object-retention --bucket ugallu --key <KEY> \
    --endpoint-url=http://seaweedfs:8333
```
