# Detonation image for script / ELF payloads (Windows payloads go to CAPEv2 - see docs/SECURITY.md).
# Build and pin by digest:
#   docker build -t soc-detonation:1 deploy/sandbox
#   docker inspect --format '{{index .RepoDigests 0}}' soc-detonation:1   -> SANDBOX_DETONATION_IMAGE=<that value>
# Contains strace (behaviour tracing) and interpreters; deliberately NO curl/wget/nc - network is disabled anyway and
# attempts to exec such tools are still visible in the strace execve log.
FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends strace python3 perl nodejs coreutils procps \
 && rm -rf /var/lib/apt/lists/* /usr/share/doc /usr/share/man \
 && (rm -f /usr/bin/curl /usr/bin/wget /bin/nc /usr/bin/nc 2>/dev/null || true) \
 && mkdir /sandbox && chown 65534:65534 /sandbox
USER 65534:65534
WORKDIR /sandbox
CMD ["sleep", "infinity"]
