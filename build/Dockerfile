# Multi-binary runtime image consumed by the helm subcharts. Build
# context expects pre-built static binaries adjacent to this file:
#
#   attestor-bin
#   ttl-bin
#   backpressure-bin
#   gitops-responder-bin
#   resolver-bin
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

FROM scratch
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY attestor-bin /bin/ugallu-attestor
COPY ttl-bin /bin/ugallu-ttl
COPY backpressure-bin /bin/ugallu-backpressure
COPY gitops-responder-bin /bin/ugallu-gitops-responder
COPY resolver-bin /bin/ugallu-resolver
USER 65532:65532
ENTRYPOINT ["/bin/ugallu-attestor"]
