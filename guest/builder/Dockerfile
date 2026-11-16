# syntax=docker/dockerfile:1
#
# orbd-image-builder: the image pipeline's tools (umoci, mkfs.ext4, GNU du) for agents
# whose host cannot run them, i.e. macOS. The agent runs one `docker run --rm
# --network none` of it per image build (crates/orbd/src/image/rootfs.rs); the rootfs is
# unpacked inside the container, only the build's work directory is shared.
#
#   docker build -t orbd-image-builder:umoci-0.6.0 guest/builder
FROM debian:13-slim@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4
SHELL ["/bin/bash", "-euo", "pipefail", "-c"]
ARG TARGETARCH
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl e2fsprogs \
    && case "$TARGETARCH" in \
        amd64) sha=b51c267ec394499e42c6fde47f240b7b7dba57ea49df0b5acd304378b82a3b71 ;; \
        arm64) sha=5cfd17f2e7a4bcf9ed67ea1b955ca893d200349b9ce6a3d3707dba415f458a1f ;; \
        *) exit 1 ;; \
       esac \
    && curl -fsSL -o /usr/local/bin/umoci "https://github.com/opencontainers/umoci/releases/download/v0.6.0/umoci.linux.$TARGETARCH" \
    && echo "$sha  /usr/local/bin/umoci" | sha256sum -c \
    && chmod 0755 /usr/local/bin/umoci \
    && apt-get purge -y curl && apt-get autoremove -y && rm -rf /var/lib/apt/lists/* \
    && umoci --version && mkfs.ext4 -V
