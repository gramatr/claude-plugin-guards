# guards/vendor/secret-guard-core/Dockerfile
#
# secret-guard has no upstream Dockerfile (it's a stateless bash+gitleaks
# script, not a resident model like its siblings) — this wraps scan.sh
# in server.py so it presents the same Docker-service shape as
# pii-guard-daemon and injection-guard-daemon for this compose stack.
#
# gitleaks is built from its release tag here, not copied out of the official
# image: v8.30.1 is the latest release but its binary bundles Go modules with
# known HIGH CVEs (klauspost/compress, x/crypto, x/text, the Go stdlib), and a
# secret scanner should not ship a vulnerable dependency. The build pins the
# tag, bumps the modules to fixed versions and uses a current Go toolchain.
# The module list below is the same as guards-unified's Dockerfile.cpu (the xz and
# rardecode bumps and x/crypto v0.56.0 clear the MEDIUM findings Trivy reported);
# guards/tests/dockerfile-go-drift.sh fails CI if the two lists differ.
# When gitleaks publishes a release that already carries these fixes, drop
# the `go get` line (and the bumps) and go back to the tag alone.
FROM golang:1.26-bookworm@sha256:fe3da92a5cb2881e4aa75e625cb0b7c50571632fb4cf340cbe53e6ccdcffdd51 AS gitleaks
ARG GITLEAKS_VERSION=v8.30.1
# The commit the release tag points at (checked 2026-10-21). A tag can be moved; a commit cannot.
ARG GITLEAKS_COMMIT=83d9cd684c87d95d656c1458ef04895a7f1cbd8e
RUN git init -q /src && cd /src \
    && git remote add origin https://github.com/gitleaks/gitleaks.git \
    && git fetch -q --depth 1 origin "${GITLEAKS_COMMIT}" \
    && git checkout -q --detach FETCH_HEAD
WORKDIR /src
RUN go get github.com/klauspost/compress@v1.18.7 golang.org/x/crypto@v0.56.0 golang.org/x/text@v0.41.0 \
       github.com/ulikunitz/xz@v0.5.15 github.com/nwaples/rardecode/v2@v2.2.0 github.com/mholt/archives@v0.1.5 \
    && go mod tidy \
    && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X github.com/zricethezav/gitleaks/v8/version.Version=${GITLEAKS_VERSION}" -o /usr/bin/gitleaks .

FROM python:3.12-slim@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704
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
