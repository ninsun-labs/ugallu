# Multi-binary runtime image consumed by the helm subcharts. Build
# context expects pre-built static binaries adjacent to this file:
#
#   attestor-bin
#   ttl-bin
#   backpressure-bin
#   gitops-responder-bin
#   resolver-bin
#   audit-detection-bin
#   forensics-bin
#   forensics-snapshot-bin
#   webhook-auditor-bin
#   dns-detect-bin
#   tenant-escape-bin
#   honeypot-bin
#   seccomp-gen-bin
#   backup-verify-bin
#   compliance-scan-bin
#   confidential-attestation-bin
#   tetragon-bridge-bin
#   ugallu-bff-bin
#   ugallu-ui-spa/                # SvelteKit static bundle (cmd/ugallu-ui/build/)
#
# Cross-compile each binary with:
#   CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w'
#
# The CA bundle is copied from an alpine builder so HTTPS calls to
# api.github.com / Fulcio / Rekor / SeaweedFS-with-TLS work from a
# scratch base. Override the entrypoint per workload via the helm
# subchart (.Values.command).
FROM alpine:3.20 AS certs
RUN apk add --no-cache ca-certificates

# Static busybox - the ugallu-ui chart's initContainer needs `cp`
# to copy /srv/www/ugallu-ui/ into a shared emptyDir for the nginx
# sidecar. The musl variant is fully static and works from scratch.
FROM busybox:1.37-musl AS busybox

FROM scratch
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=busybox /bin/busybox /bin/busybox
COPY attestor-bin /bin/ugallu-attestor
COPY ttl-bin /bin/ugallu-ttl
COPY backpressure-bin /bin/ugallu-backpressure
COPY gitops-responder-bin /bin/ugallu-gitops-responder
COPY resolver-bin /bin/ugallu-resolver
COPY audit-detection-bin /bin/ugallu-audit-detection
COPY forensics-bin /bin/ugallu-forensics
COPY forensics-snapshot-bin /bin/ugallu-forensics-snapshot
COPY webhook-auditor-bin /bin/ugallu-webhook-auditor
COPY dns-detect-bin /bin/ugallu-dns-detect
COPY tenant-escape-bin /bin/ugallu-tenant-escape
COPY honeypot-bin /bin/ugallu-honeypot
COPY seccomp-gen-bin /bin/ugallu-seccomp-gen
COPY backup-verify-bin /bin/ugallu-backup-verify
COPY compliance-scan-bin /bin/ugallu-compliance-scan
COPY confidential-attestation-bin /bin/ugallu-confidential-attestation
COPY tetragon-bridge-bin /bin/tetragon-bridge
COPY ugallu-bff-bin /bin/ugallu-bff
# SvelteKit static bundle - served by the nginx-distroless sidecar
# in the ugallu-ui Pod through a shared emptyDir mount populated
# by the chart's initContainer (see charts/ugallu-ui).
COPY ugallu-ui-spa/ /srv/www/ugallu-ui/
USER 65532:65532
ENTRYPOINT ["/bin/ugallu-attestor"]
