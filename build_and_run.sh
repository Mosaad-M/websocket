#!/bin/bash
# Build a Mojo file and run it.
# No OpenSSL dependency — TLS is provided by tls_pure (pure Mojo).
# Usage: ./build_and_run.sh <file.mojo> [args...]
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MOJO_FILE="$1"
shift

BASENAME="$(basename "$MOJO_FILE" .mojo)"
BUILD_DIR="$SCRIPT_DIR/.build"
mkdir -p "$BUILD_DIR"

# Use mojo-pkg flags if available (CI), else fall back to tls_pure (local dev)
if [ -f "$SCRIPT_DIR/.mojo_flags" ]; then
    FLAGS=$(cat "$SCRIPT_DIR/.mojo_flags")
else
    FLAGS="-I ${TLS_PURE:-../tls_pure}"
fi

# Detect CPU target
if [ "$(uname -m)" = "arm64" ] || [ "$(uname -m)" = "aarch64" ]; then
    MCPU_FLAG="--mcpu apple-m1"
else
    MCPU_FLAG="--mcpu x86-64-v2"
fi

mojo build "$MOJO_FILE" -o "$BUILD_DIR/$BASENAME" \
    $MCPU_FLAG \
    -I "$SCRIPT_DIR" \
    $FLAGS

"$BUILD_DIR/$BASENAME" "$@"
