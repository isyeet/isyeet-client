#!/bin/bash
set -euo pipefail
umask 077

APP_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"
RUN_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/isyeet-lifecycle.XXXXXX")"
trap 'rm -rf "$RUN_ROOT"' EXIT

# No app build, Simulator, network, Keychain, credentials or Rust state is used.
# Keep assertions enabled and all compiler output in this private temporary tree.
xcrun swiftc -parse-as-library -Onone \
    -module-cache-path "$RUN_ROOT/module-cache" \
    "$APP_ROOT/Sources/ISYEETDomain/Domain.swift" \
    "$APP_ROOT/ISYEET/AppModel.swift" \
    "$APP_ROOT/Tests/AppModelLifecycle/Harness.swift" \
    -o "$RUN_ROOT/check-lifecycle"
"$RUN_ROOT/check-lifecycle"
