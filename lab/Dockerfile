# Lab image: production brolga binary + offline fixtures + one-shot scripts.
# Self-contained so Compose works against a remote Docker context (no host bind mounts).
# syntax=docker/dockerfile:1

FROM brolga:lab AS binary

FROM alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce

RUN addgroup -g 65532 -S brolga \
    && adduser -u 65532 -S -G brolga -h /data -s /sbin/nologin brolga \
    && mkdir -p /data /feeds /scripts /output \
    && chown brolga:brolga /data /output

COPY --from=binary /usr/local/bin/brolga /usr/local/bin/brolga
COPY fixtures /feeds
COPY scripts /scripts
RUN chmod 755 /scripts/*.sh \
    && chown -R brolga:brolga /feeds /scripts

USER brolga:brolga
WORKDIR /data
ENTRYPOINT ["/usr/local/bin/brolga"]
CMD ["doctor"]
