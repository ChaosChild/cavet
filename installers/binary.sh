#!/usr/bin/env bash
# cavet binary installer (bash) - resolves a GitHub release (default: latest),
# downloads the OS/arch archive, verifies it against checksums.txt (and the
# Sigstore bundle when cosign is installed), and installs the cavet binary.
#
# Advertised one-liner (the pipe form passes no arguments - it installs the
# latest release):
#   curl -fsSL https://raw.githubusercontent.com/ChaosChild/cavet/main/installers/binary.sh | bash
# Pinned install (bash -s -- forwards arguments through the pipe):
#   curl -fsSL https://raw.githubusercontent.com/ChaosChild/cavet/main/installers/binary.sh | bash -s -- --version 0.1.0
# From a clone:
#   bash installers/binary.sh --version 0.1.0 --dir /usr/local/bin
#
# --version <x.y.z|latest>  release to install (default: latest)
# --dir <path>              install directory (default: $CAVET_INSTALL_DIR
#                           or $HOME/.local/bin)

set -euo pipefail

REPO=ChaosChild/cavet
VERSION=latest
DIR="${CAVET_INSTALL_DIR:-$HOME/.local/bin}"

while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="${2:?--version needs a value}"; shift 2 ;;
    --version=*) VERSION="${1#--version=}"; shift ;;
    --dir) DIR="${2:?--dir needs a value}"; shift 2 ;;
    --dir=*) DIR="${1#--dir=}"; shift ;;
    *) echo "unknown argument: $1 (usage: $0 [--version <x.y.z|latest>] [--dir <path>])" >&2; exit 2 ;;
  esac
done

OS=$(uname -s)
ARCH=$(uname -m)
case "$OS" in
  Darwin) OS=darwin ;;
  Linux) OS=linux ;;
  *) echo "unsupported OS '$OS' (uname -s); supported platforms: darwin/amd64, darwin/arm64, linux/amd64, linux/arm64 - on Windows use installers/binary.ps1" >&2; exit 1 ;;
esac
case "$ARCH" in
  x86_64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "unsupported architecture '$ARCH' (uname -m); supported platforms: darwin/amd64, darwin/arm64, linux/amd64, linux/arm64" >&2; exit 1 ;;
esac

if [ "$VERSION" = latest ]; then
  VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" |
    sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)
  [ -n "$VERSION" ] || { echo "could not resolve latest release from the GitHub API" >&2; exit 1; }
fi
VER=${VERSION#v}
BASE="https://github.com/$REPO/releases/download/v$VER"
ARCHIVE="cavet_${VER}_${OS}_${ARCH}.tar.gz"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

fetch() { # fetch <output-file> <url> - hard error naming the URL on failure
  curl -fsSL -o "$1" "$2" || { echo "download failed: $2 (does release v$VER exist? see https://github.com/$REPO/releases)" >&2; exit 1; }
}

echo "installing cavet $VER for $OS/$ARCH into $DIR"
fetch "$TMP/checksums.txt" "$BASE/checksums.txt"
fetch "$TMP/$ARCHIVE" "$BASE/$ARCHIVE"

# 1. checksum: sha256sum on linux, shasum -a 256 on darwin
if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL=$(sha256sum "$TMP/$ARCHIVE" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
  ACTUAL=$(shasum -a 256 "$TMP/$ARCHIVE" | awk '{print $1}')
else
  echo "neither sha256sum nor shasum is installed; cannot verify the download" >&2
  exit 1
fi
EXPECTED=$(awk -v f="$ARCHIVE" '$2 == f {print $1}' "$TMP/checksums.txt")
[ -n "$EXPECTED" ] || { echo "checksums.txt has no entry for $ARCHIVE" >&2; exit 1; }
[ "$ACTUAL" = "$EXPECTED" ] || { echo "checksum mismatch for $ARCHIVE - download deleted, nothing installed" >&2; exit 1; }

# 2. signature: verified only when cosign is on PATH (hard error on failure)
if command -v cosign >/dev/null 2>&1; then
  fetch "$TMP/checksums.txt.sigstore.json" "$BASE/checksums.txt.sigstore.json"
  cosign verify-blob --bundle "$TMP/checksums.txt.sigstore.json" \
    --certificate-identity-regexp '^https://github\.com/ChaosChild/cavet/\.github/workflows/release\.yml@' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    "$TMP/checksums.txt" || { echo "signature verification failed - nothing installed" >&2; exit 1; }
else
  echo "checksum verified; signature not verified (cosign not installed)"
fi

# 3. install
mkdir -p "$DIR"
tar -xzf "$TMP/$ARCHIVE" -C "$TMP"
install -m 0755 "$TMP/cavet" "$DIR/cavet"

echo "installed : $DIR/cavet"
if VER_OUT=$("$DIR/cavet" --version 2>&1); then
  echo "version   : $VER_OUT"
fi
case ":$PATH:" in
  *":$DIR:"*) ;;
  *)
    echo "note: $DIR is not on your PATH. Fix (then log out and back in):"
    echo "  echo 'export PATH=\"\$PATH:$DIR\"' >> ~/.profile"
    ;;
esac
