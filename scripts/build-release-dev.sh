#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DIST_DIR="$REPO_DIR/target/dist"
TARGET="x86_64-unknown-linux-musl"
BUILD_DIR="$REPO_DIR/target/$TARGET/release"

if ! command -v docker >/dev/null 2>&1; then
  echo "error: docker is required" >&2
  exit 1
fi

if ! command -v strip >/dev/null 2>&1; then
  echo "error: strip is required" >&2
  exit 1
fi

mkdir -p "$DIST_DIR"

echo "==> Building static musl binaries in Docker (rust:latest)..."
docker run --rm -v "$REPO_DIR:/src" rust:latest sh -c \
  "apt-get update -qq && apt-get install -y -qq musl-tools >/dev/null 2>&1 && \
   rustup target add $TARGET && \
   cd /src && cargo build --release --target $TARGET && \
   strip target/$TARGET/release/wsh target/$TARGET/release/wsh-auditd && \
   chmod 755 target/$TARGET/release/wsh target/$TARGET/release/wsh-auditd"

WSH_BIN="$BUILD_DIR/wsh"
AUDITD_BIN="$BUILD_DIR/wsh-auditd"

if [[ ! -f "$WSH_BIN" || ! -f "$AUDITD_BIN" ]]; then
  echo "error: build output missing; expected $WSH_BIN and $AUDITD_BIN" >&2
  exit 1
fi

echo "==> Copying artifacts to target/dist/..."
cp "$WSH_BIN" "$DIST_DIR/wsh"
cp "$AUDITD_BIN" "$DIST_DIR/wsh-auditd"

TARBALL="$DIST_DIR/wsh-linux-x86_64.tar.gz"
CHECKSUM="$TARBALL.sha256"

tar -czf "$TARBALL" -C "$DIST_DIR" wsh wsh-auditd

if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "$TARBALL" > "$CHECKSUM"
elif command -v shasum >/dev/null 2>&1; then
  shasum -a 256 "$TARBALL" > "$CHECKSUM"
else
  openssl dgst -sha256 "$TARBALL" | sed 's/^SHA2-256(//; s/)= /  /' > "$CHECKSUM"
fi

echo "==> Artifact details"
file "$DIST_DIR/wsh"
file "$DIST_DIR/wsh-auditd"
ls -lh "$DIST_DIR/wsh" "$DIST_DIR/wsh-auditd" "$TARBALL" "$CHECKSUM"
echo "==> Done"
