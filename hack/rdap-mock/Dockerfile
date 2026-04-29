# Tiny static-binary image for the dns-detect young-domain mock.
FROM scratch
COPY rdap-mock-bin /rdap-mock
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/rdap-mock"]
