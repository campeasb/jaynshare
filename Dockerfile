# The platform image: the Jaynshare binary, a public TLS root
# bundle, LICENSE and NOTICE.md. Nothing else — no shell, no package manager,
# no libc, no client kit.
#
# The binary is an input, never compiled here: the image payload must be the
# same bytes as the release artefact, so the container build MUST NOT produce
# a second binary. Build with, for example:
#
#   cargo build --release --target x86_64-unknown-linux-musl --target aarch64-unknown-linux-musl
#   docker buildx build --platform linux/amd64,linux/arm64 \
#     --build-context bin=<dir holding amd64/jaynshare and arm64/jaynshare> \
#     --build-arg VERSION=0.1.0-m3 --build-arg COMMIT="$(git rev-parse HEAD)" .
#
# The Linux payload is statically linked (musl) because a `scratch` image has no
# dynamic loader, and no libc enters the image.
#
# The root bundle comes from a digest-pinned alpine stage (the same Mozilla CA
# set Alpine's `ca-certificates-bundle` ships, MPL-2.0); the digest below is the
# index digest of `alpine:3.22`, read with `docker buildx imagetools inspect`.
# The bundle stage is architecture-free: it runs on the build machine, so no
# emulated `RUN` is needed for the multi-platform build.
FROM --platform=$BUILDPLATFORM alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8 AS roots
RUN mkdir -p /out/var/lib/jaynshare /out/etc/jaynshare

FROM scratch

ARG VERSION
ARG COMMIT
# Each platform takes its own binary from the `bin` build context: a directory
# holding `amd64/jaynshare` and `arm64/jaynshare`.
ARG TARGETARCH
# The labels state version, commit, license and source repository.
LABEL org.opencontainers.image.title="jaynshare" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/jaynlabs/jaynshare"

COPY --from=bin --chmod=0555 ${TARGETARCH}/jaynshare /usr/local/bin/jaynshare
COPY --from=roots /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY LICENSE NOTICE.md /

# A fixed numeric non-root uid/gid and a fixed home. The home is where
# the project volume is mounted, so state, logs and trust material land
# there; a named volume copies the image directory's owner, so the service home
# must be the service uid's or the volume is unwritable for it. This COPY comes
# before WORKDIR: WORKDIR would create the directory first, and a COPY into an
# existing directory does not re-chmod it.
COPY --from=roots --chown=10001:10001 --chmod=0700 /out/var/lib/jaynshare /var/lib/jaynshare
# The configuration file is bind-mounted alone at
# /etc/jaynshare/config.toml, so its directory is the image's. The server
# refuses a configuration directory broader than 0700, so the image carries it
# as the service uid's, owner-only.
COPY --from=roots --chown=10001:10001 --chmod=0700 /out/etc/jaynshare /etc/jaynshare

USER 10001:10001
ENV HOME=/var/lib/jaynshare \
    JAYNSHARE_CONFIG=/etc/jaynshare/config.toml
WORKDIR /var/lib/jaynshare

# The default process is the foreground server.
ENTRYPOINT ["/usr/local/bin/jaynshare"]
CMD ["serve"]

# The health check is the binary's own loopback operator status read, in the
# output-free `--check` form so nothing is written to the health log.
HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=3 \
  CMD ["/usr/local/bin/jaynshare", "status", "--check"]
