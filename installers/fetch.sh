#!/usr/bin/env bash
# cavet fetch-installer (bash) - installs a cavet harness installer without a
# local clone: resolves the requested release (default: latest), downloads the
# tag tarball from GitHub, extracts it to a temp dir, and runs
# installers/<harness>.sh from there. Everything else on the command line
# (e.g. --target <dir>) is forwarded to that installer verbatim.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/ChaosChild/cavet/main/installers/fetch.sh \
#     | bash -s -- --harness claude-code
#   bash fetch.sh --harness claude-code --version 0.1.0 --target /tmp/x
#
# CAVET_INSTALL_TARGET / --target pass through to the harness installer.
# CAVET_FETCH_SOURCE=<dir> (test hook): use <dir> as the already-extracted
# source tree instead of downloading anything.

set -euo pipefail

HARNESSES="claude-code codex opencode pi hermes zcode deepseek"
HARNESS=""
VERSION="latest"
FORWARD=()

while [ $# -gt 0 ]; do
  case "$1" in
    --harness) HARNESS="${2:?--harness needs a value}"; shift 2 ;;
    --harness=*) HARNESS="${1#--harness=}"; shift ;;
    --version) VERSION="${2:?--version needs a value}"; shift 2 ;;
    --version=*) VERSION="${1#--version=}"; shift ;;
    *) FORWARD+=("$1"); shift ;; # forwarded to the harness installer
  esac
done

[ -n "$HARNESS" ] || { echo "usage: $0 --harness <${HARNESSES// /|}> [--version <x.y.z|latest>] [--target <dir>]" >&2; exit 2; }
case " $HARNESSES " in
  *" $HARNESS "*) ;;
  *) echo "unknown harness '$HARNESS' (want one of: $HARNESSES)" >&2; exit 2 ;;
esac

if [ -n "${CAVET_FETCH_SOURCE:-}" ]; then
  SRC=$CAVET_FETCH_SOURCE
else
  if [ "$VERSION" = latest ]; then
    VERSION=$(curl -fsSL https://api.github.com/repos/ChaosChild/cavet/releases/latest |
      sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)
    [ -n "$VERSION" ] || { echo "could not resolve latest release from the GitHub API" >&2; exit 1; }
  fi
  TMP=$(mktemp -d)
  trap 'rm -rf "$TMP"' EXIT
  echo "fetching cavet ${VERSION#v}"
  curl -fsSL -o "$TMP/src.tar.gz" "https://github.com/ChaosChild/cavet/archive/refs/tags/v${VERSION#v}.tar.gz"
  tar -xzf "$TMP/src.tar.gz" -C "$TMP"
  SRC=$(ls -d "$TMP"/cavet-*/ | head -1)
  [ -n "$SRC" ] || { echo "archive did not extract a cavet-* directory" >&2; exit 1; }
fi

INSTALLER=$SRC/installers/$HARNESS.sh
[ -f "$INSTALLER" ] || { echo "installer not found: $INSTALLER" >&2; exit 1; }
exec bash "$INSTALLER" ${FORWARD[@]+"${FORWARD[@]}"}
