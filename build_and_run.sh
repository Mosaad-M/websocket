#!/bin/bash
# Build a Mojo file with errno_helper support and run it.
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

mojo build "$MOJO_FILE" -o "$BUILD_DIR/$BASENAME" \
    -I "$SCRIPT_DIR" \
    $FLAGS \
    -Xlinker -L"$SCRIPT_DIR" \
    -Xlinker -lerrno_helper \
    -Xlinker -rpath \
    -Xlinker "$SCRIPT_DIR"

"$BUILD_DIR/$BASENAME" "$@"
