# syntax=docker/dockerfile:1

# The Brolga container image.
#
# Two stages, because the runtime layer must not carry a toolchain. A compiler, a linker, and a
# package index are attack surface, and a tool whose whole job is parsing untrusted intelligence
# has no use for any of them once it has been built. What ships is the `brolga` binary, a libc,
# and a shell.
#
# Both bases are pinned by digest rather than by tag. `alpine:3.22` is a different image this
# month than it was last month, and an image that cannot be rebuilt byte-for-byte cannot be
# audited after an incident. Each digest below is a multi-architecture index, so amd64 and arm64
# hosts resolve the correct manifest from the same pin.

# rust:1.88-alpine3.22 — 1.88.0 is the MSRV that ADR 0002 declares and that CI pins a job to.
# Building on the floor rather than on `stable` means the image cannot quietly start depending on
# a compiler feature the project has not committed to supporting.
FROM rust:1.88-alpine3.22@sha256:9dfaae478ecd298b6b5a039e1f2cc4fc040fc818a2de9aa78fa714dea036574d AS builder

# `rusqlite` is taken with the `bundled` feature, which compiles SQLite from C source, and that
# needs a C toolchain the Rust Alpine image does not ship. Nothing else is installed: `flate2` is
# configured with its pure-Rust backend precisely so that a second C build is not required here.
#
# This `apk add` is the one input to the image that a digest does not pin — it resolves against
# the Alpine repositories at build time. Say so rather than imply the build is hermetic.
RUN apk add --no-cache build-base

WORKDIR /usr/src/brolga
COPY . .

# Cache mounts rather than the usual copy-manifests-and-build-a-stub trick. That trick has to be
# kept in step with seven crate manifests by hand, and it fails silently the first time someone
# adds a crate and forgets. `--locked` refuses to update `Cargo.lock`, so the image is built from
# the dependency versions the repository has actually tested. The binary is copied out of the
# cache mount in the same layer, because the mount does not survive the instruction.
# Optional features (e.g. `postgres`) for server-mode images. Default stays lean (ADR 0001 §3).
ARG BROLGA_FEATURES=
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/src/brolga/target,sharing=locked \
    if [ -n "$BROLGA_FEATURES" ]; then \
      cargo build --locked --release --package brolga-cli --features "$BROLGA_FEATURES"; \
    else \
      cargo build --locked --release --package brolga-cli; \
    fi \
    && cp target/release/brolga /usr/local/bin/brolga

# alpine:3.22
#
# Not `scratch`: the official Rust Alpine image sets `-C target-feature=-crt-static`, so the
# binary links dynamically against musl and needs a loader. Alpine supplies that in about eight
# megabytes, and it supplies a shell, which is the difference between diagnosing a stuck
# deployment and guessing at it.
#
# No `ca-certificates` and no network client of any kind. Brolga makes no outbound connections;
# connectors are `v0.6.0`, and this is the line to revisit when they arrive.
FROM alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce AS runtime

LABEL org.opencontainers.image.title="brolga" \
      org.opencontainers.image.description="Threat intelligence context engine" \
      org.opencontainers.image.source="https://github.com/jusso-dev/Brolga" \
      org.opencontainers.image.licenses="MIT"

# A fixed high uid, not a name looked up at runtime. `docker run --user 65532:65532` and a
# Kubernetes `runAsUser` both want the number, and a numeric id keeps the volume's ownership
# meaningful when the image is rebuilt.
#
# `/data` is created and chowned here rather than left to the volume mount. Docker initialises a
# fresh named volume from whatever the image has at the mount point, so a `/data` that does not
# exist in the image becomes a root-owned directory the non-root user cannot write to — a failure
# that only appears on the operator's first run, never on a rebuild.
RUN addgroup -g 65532 -S brolga \
    && adduser -u 65532 -S -G brolga -h /data -s /sbin/nologin brolga \
    && mkdir -p /data /feeds \
    && chown brolga:brolga /data

COPY --from=builder /usr/local/bin/brolga /usr/local/bin/brolga

USER brolga:brolga

# Every default path in the CLI — `brolga.sqlite` for the database, `brolga.yaml` for the starter
# configuration — is relative to the working directory. Putting the working directory on the
# volume means the operator gets persistence without passing a single path flag, and it means a
# forgotten flag writes to the volume rather than to a layer that disappears with the container.
WORKDIR /data

# No `HEALTHCHECK`. Brolga is a command that runs and exits, not a daemon, so there is no long-
# lived process for a health probe to describe. `brolga doctor` is the equivalent, and it is the
# default command below.
ENTRYPOINT ["/usr/local/bin/brolga"]
CMD ["doctor"]
