# syntax=docker/dockerfile:1
#
# cavet-engine — digest-pinned scanner image (engine-spec.md).
# Everything is baked at build time; nothing installs at runtime (spec §7.2.1).
#
# One build-args block is the only place versions appear (engine-spec §2.1).

ARG OPENGREP_VERSION=1.27.1
ARG GITLEAKS_VERSION=8.30.1
ARG TRIVY_VERSION=0.74.0
ARG CHECKOV_VERSION=3.3.16
ARG OPENGREP_RULES_SHA=f1d2b562b414783763fd02a6ed2736eaed622efa

# ---------------------------------------------------------------- base ------
FROM debian:bookworm-slim AS base
# -y upgrade: the base snapshot's debs go stale between releases (e.g. libexpat1
# CVE-2026-56408); upgrade picks up every fixed deb security update at build time.
RUN apt-get update && apt-get -y upgrade \
    && apt-get install -y --no-install-recommends \
        locales git ca-certificates curl \
    && sed -i 's/^# *C.UTF-8 UTF-8/C.UTF-8 UTF-8/' /etc/locale.gen \
    && locale-gen \
    && rm -rf /var/lib/apt/lists/*
# Opengrep aborts with UnicodeDecodeError under a non-UTF-8 locale (spike §6).
ENV LANG=C.UTF-8 LC_ALL=C.UTF-8
ENV TRIVY_CACHE_DIR=/opt/trivy-cache
ENV OPENGREP_RULES=/opt/opengrep-rules
ENV GITLEAKS_CONFIG=/opt/gitleaks.toml

# Gitleaks (MIT) — source-built on a current toolchain.
# Upstream v8.30.1 release binaries are built with Go 1.24.11 + x/crypto
# v0.35.0 and carry open stdlib/x CVEs (rc1 scan: 1 CRITICAL, 31 HIGH) with no
# newer upstream release. Building the pinned tag with golang:1.26 fixes the
# toolchain; the x/* bumps deliberately go past the upstream pin (dependency
# upgrades only, behaviour unchanged; go mod tidy prunes anything unused).
# Supply chain: this replaces the release-tarball sha256 pin — the pinned git
# tag plus go's own module-hash verification (checksum db) cover provenance.
# gore2regex + CGO_ENABLED=0 mirror the upstream release build (go-re2 is
# pure-Go wazero, no cgo needed); -ldflags injects the version so
# `gitleaks --version` still reports the tag.
FROM golang:1.26-bookworm AS gitleaks-build
ARG GITLEAKS_VERSION
RUN git clone --depth 1 --branch "v${GITLEAKS_VERSION}" https://github.com/gitleaks/gitleaks /src \
    && cd /src \
    && go get golang.org/x/crypto@latest golang.org/x/net@latest \
    && go mod tidy \
    && CGO_ENABLED=0 go build -tags gore2regex -trimpath \
        -ldflags "-s -w -X=github.com/zricethezav/gitleaks/v8/version.Version=${GITLEAKS_VERSION}" \
        -o /out/gitleaks .

# ------------------------------------------------------------ scanners ------
FROM base AS scanners
ARG TARGETARCH
ARG OPENGREP_VERSION
ARG TRIVY_VERSION
ARG CHECKOV_VERSION
COPY --from=gitleaks-build /out/gitleaks /usr/local/bin/gitleaks

# Trivy (Apache-2.0).
RUN set -e; \
    case "$TARGETARCH" in \
        amd64) tarch=Linux-64bit;  sha=2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a ;; \
        arm64) tarch=Linux-ARM64;  sha=b94ce1976bbf3c15b514b605ee88be7c6d94a29be2302847ff01cb794d47aad5 ;; \
        *) echo "unsupported TARGETARCH $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/trivy.tar.gz \
        "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_${tarch}.tar.gz"; \
    echo "$sha /tmp/trivy.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy; \
    chmod +x /usr/local/bin/trivy; \
    rm /tmp/trivy.tar.gz

# Opengrep (engine LGPL-2.1) — self-contained manylinux binary.
RUN set -e; \
    case "$TARGETARCH" in \
        amd64) oarch=manylinux_x86;      sha=58053da76672bbeb5b0a5441021c58338707052e10f81d777140ca879bd491ce ;; \
        arm64) oarch=manylinux_aarch64;  sha=96ee2caddd5f17821ae6952774a91c8781778bfa9af1ace83645444c0edc6c97 ;; \
        *) echo "unsupported TARGETARCH $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /usr/local/bin/opengrep \
        "https://github.com/opengrep/opengrep/releases/download/v${OPENGREP_VERSION}/opengrep_${oarch}"; \
    echo "$sha /usr/local/bin/opengrep" | sha256sum -c -; \
    chmod +x /usr/local/bin/opengrep

# Checkov (Apache-2.0), opt-in per repository (config.scanners.checkov).
# ponytail: pip-installed in a venv; pin drift is contained to this layer.
# setuptools: Debian's ensurepip bundles 66.1.1 into every venv (CVE-2024-6345,
# CVE-2025-47273); checkov does not depend on it, so bump it past the fixes.
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-venv \
    && python3 -m venv /opt/checkov \
    && /opt/checkov/bin/pip install --no-cache-dir --upgrade "setuptools>=78.1.1" \
    && /opt/checkov/bin/pip install --no-cache-dir "checkov==${CHECKOV_VERSION}" \
    && ln -s /opt/checkov/bin/checkov /usr/local/bin/checkov \
    && apt-get purge -y python3-venv && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

# --------------------------------------------------------------- rules ------
# Layer order encodes engine-spec §3: base → binaries → rules → data.
FROM scanners AS rules
ARG OPENGREP_RULES_SHA
COPY curate-rules.sh /usr/local/bin/curate-rules.sh
RUN chmod +x /usr/local/bin/curate-rules.sh \
    && git init /tmp/rules \
    && git -C /tmp/rules fetch --depth 1 https://github.com/opengrep/opengrep-rules "$OPENGREP_RULES_SHA" \
    && git -C /tmp/rules checkout --quiet FETCH_HEAD \
    && /usr/local/bin/curate-rules.sh /tmp/rules /opt/opengrep-rules \
    && rm -rf /tmp/rules

# ---------------------------------------------------------- trivy data ------
FROM scanners AS trivy-data-core
# Vulnerability DB baked in; determinism at scan time comes from the offline
# flags cli-spec §7 mandates, never a runtime refresh (spec §7.5).
RUN trivy image --download-db-only
# Misconfig policy bundle: Trivy downloads it on first misconfig scan, so a
# seeded scan at build time bakes it (spike §4, engine-spec §5).
RUN set -e; \
    mkdir -p /seed; \
    printf 'resource "aws_s3_bucket" "b" {}\n' > /seed/main.tf; \
    trivy fs --scanners misconfig --skip-db-update /seed || true; \
    rm -rf /seed; \
    test -d /opt/trivy-cache/policy/content

FROM trivy-data-core AS trivy-data-full
# java-db: only needed for JARs lacking a resolvable pom; excluded from core
# (spec §7.2.1).
RUN trivy image --download-java-db-only

# -------------------------------------------------------------- finals ------
FROM rules AS final-core
COPY --from=trivy-data-core /opt/trivy-cache /opt/trivy-cache
COPY entrypoint.sh /usr/local/bin/cavet-entrypoint.sh
COPY healthcheck     /usr/local/bin/cavet-healthcheck
COPY gitleaks.toml   /opt/gitleaks.toml
COPY LICENSES.md     /LICENSES.md
RUN chmod +x /usr/local/bin/cavet-entrypoint.sh /usr/local/bin/cavet-healthcheck

# engine-spec §6.3: CLI passes --user uid:gid on Linux hosts; arbitrary uids
# need a writable HOME (git config --global) and pre-existing scratch dirs
# (entrypoint mkdir -p must no-op, not create). Root default is unaffected.
ENV HOME=/tmp
RUN mkdir -p /reports /scan && chmod 0777 /reports /scan
HEALTHCHECK CMD ["/usr/local/bin/cavet-healthcheck"]
ENTRYPOINT ["/usr/local/bin/cavet-entrypoint.sh"]

FROM rules AS final-full
COPY --from=trivy-data-full /opt/trivy-cache /opt/trivy-cache
COPY entrypoint.sh /usr/local/bin/cavet-entrypoint.sh
COPY healthcheck     /usr/local/bin/cavet-healthcheck
COPY gitleaks.toml   /opt/gitleaks.toml
COPY LICENSES.md     /LICENSES.md
RUN chmod +x /usr/local/bin/cavet-entrypoint.sh /usr/local/bin/cavet-healthcheck

# engine-spec §6.3: CLI passes --user uid:gid on Linux hosts; arbitrary uids
# need a writable HOME (git config --global) and pre-existing scratch dirs
# (entrypoint mkdir -p must no-op, not create). Root default is unaffected.
ENV HOME=/tmp
RUN mkdir -p /reports /scan && chmod 0777 /reports /scan
HEALTHCHECK CMD ["/usr/local/bin/cavet-healthcheck"]
ENTRYPOINT ["/usr/local/bin/cavet-entrypoint.sh"]
