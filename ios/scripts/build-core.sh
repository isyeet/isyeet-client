#!/bin/bash
set -euo pipefail
APP_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BACKEND_ROOT="${ISYEET_BACKEND_PATH:-$(dirname "$APP_ROOT")/isyeet-backend}"
export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"
test -f "$BACKEND_ROOT/crates/client/include/isyeet.h"
for target in aarch64-apple-ios aarch64-apple-ios-sim; do
    if ! rustup target list --installed | /usr/bin/grep -qx "$target"; then
        echo "Install the required Rust target first: rustup target add $target" >&2
        exit 1
    fi
    if [[ "$target" == aarch64-apple-ios ]]; then SDK=iphoneos; else SDK=iphonesimulator; fi
    SDKROOT="$(xcrun --sdk "$SDK" --show-sdk-path)" cargo build \
        --manifest-path "$BACKEND_ROOT/Cargo.toml" --locked --release \
        -p isyeet-client --lib --no-default-features --target "$target"
done
OUTPUT="$APP_ROOT/Frameworks/IsyeetCore.xcframework"
if [[ -d "$OUTPUT" ]]; then rm -rf "$OUTPUT"; fi
xcodebuild -create-xcframework \
    -library "$BACKEND_ROOT/target/aarch64-apple-ios/release/libisyeet_client.a" \
    -headers "$BACKEND_ROOT/crates/client/include" \
    -library "$BACKEND_ROOT/target/aarch64-apple-ios-sim/release/libisyeet_client.a" \
    -headers "$BACKEND_ROOT/crates/client/include" \
    -output "$OUTPUT"
