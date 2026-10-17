# guards/vendor/secret-guard-core/Dockerfile
#
# secret-guard has no upstream Dockerfile (it's a stateless bash+gitleaks
# script, not a resident model like its siblings) — this wraps scan.sh
# in server.py so it presents the same Docker-service shape as
# pii-guard-daemon and injection-guard-daemon for this compose stack.
#
# Base: the official gitleaks image, not python:3.12-slim + a manual
# binary download — gitleaks publishes its own image specifically so
# downstream Dockerfiles can copy the binary out of it rather than
# re-implementing "detect the right release asset for this arch."
FROM ghcr.io/gitleaks/gitleaks:v8.30.1 AS gitleaks

FROM python:3.12-slim
COPY --from=gitleaks /usr/bin/gitleaks /usr/bin/gitleaks
RUN apt-get update && apt-get install -y --no-install-recommends jq bash \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY scan.sh server.py ./
RUN chmod +x scan.sh

# Same reasoning as pii-guard/injection-guard's Dockerfiles: binding
# 0.0.0.0 is only correct INSIDE Docker's isolated network namespace, so
# the port-publish step (compose's "127.0.0.1:PORT:PORT") controls who
# can actually reach it from the host. config default outside a
# container should stay 127.0.0.1 — set here, not in server.py, same
# split pii-guard/injection-guard use between config.py and Dockerfile.
ENV SECRET_GUARD_HOST=0.0.0.0
ENV SECRET_GUARD_PORT=8732

EXPOSE 8732

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8732/health', timeout=3)" || exit 1

CMD ["python", "server.py"]
