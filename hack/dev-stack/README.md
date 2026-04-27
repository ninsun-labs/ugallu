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

## Resolver e2e (Phase 1+2+3)

The resolver subchart can be smoke-tested on the same kind cluster
once a real image is loaded. Build the binary with `ko`, override
`resolver.image.*`, set `resolver.placeholder=false` and
`resolver.args=["--enable-ebpf-tracker=true",...]`, then verify the
gRPC service via `grpcurl` against the DaemonSet.

```bash
# port-forward + import the resolver proto from the SDK
kubectl port-forward -n ugallu-system-privileged daemonset/ugallu-resolver 9000:9000 &
grpcurl -plaintext \
  -import-path sdk/proto -proto resolver/v1/resolver.proto \
  -d '{"username":"system:serviceaccount:default:default"}' \
  localhost:9000 ugallu.resolver.v1.Resolver/ResolveBySAUsername
```

### Known limitation: kind + rootless podman + Phase 2/3

The cgroup walker (Phase 2) and eBPF live tracker (Phase 3) are
**not exercisable** on a kind cluster running under rootless podman:

1. **Rootless userns blocks BPF map create**: even with CAP_BPF +
   CAP_PERFMON + CAP_SYS_ADMIN added to the resolver pod, the kernel
   denies BPF object creation when the call happens from a non-init
   user namespace. cilium/ebpf surfaces this as a generic
   "operation not permitted (MEMLOCK may be too low)" error.
2. **Non-standard cgroup root**: kind+podman sets kubelet's
   `cgroupRoot: /kubelet` instead of the systemd convention
   (`/kubepods.slice/...`). `ParseCgroupPath` won't recognise the
   former because it's a kind-specific quirk; production K8s nodes
   (RKE2, EKS, GKE) follow the systemd convention.

The resolver reacts gracefully: BPF load failure is logged
(`eBPF tracker load failed; falling back to rescan`) and the
DaemonSet stays Ready, serving informer-backed Phase 1 RPCs
(`ResolveByPodUID`, `ResolveByPodIP`, `ResolveByContainerID`,
`ResolveBySAUsername`) without interruption.

**For a real Phase 2+3 e2e** you need either:
- A kind cluster on a rootful container runtime
  (`sudo systemctl start podman.socket` + `KIND_EXPERIMENTAL_PROVIDER`
  pointing at the system service), or
- A bare K8s node (RKE2, k3s, kubeadm-on-VM) where /kubepods.slice
  is real and the kubelet runs under PID 1's user namespace.

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
