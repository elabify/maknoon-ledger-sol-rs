#!/usr/bin/env bash
# Build LedgerSolCore.xcframework: arm64 device + arm64/x86_64 sim.
#
# Output:
#   ios/LedgerSolCore.xcframework  drop this into Xcode
#   ios/bindings/Swift/             generated Swift glue
#
# Each platform slice is wrapped as a `.framework` bundle inside the
# xcframework. That namespaces the modulemap so multiple uniffi-
# generated xcframeworks (LedgerBtcCore, LedgerSolCore, future
# ledger-eth-rs / trezor-rs) can coexist in one app without their
# `module.modulemap` files colliding in `<DerivedData>/include/`.
#
# Prerequisites (one-time): `make setup-ios-targets`

set -euo pipefail

CRATE=ledger-sol-core
LIB=libledger_sol_core
FRAMEWORK=LedgerSolCore
PROFILE=release
PROFILE_DIR=release

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if command -v rustup >/dev/null 2>&1; then
    CARGO="$(rustup which cargo)"
    export RUSTC="$(rustup which rustc)"
else
    CARGO="cargo"
fi
echo "[ios] using cargo: $CARGO"
echo "[ios] using rustc: ${RUSTC:-cargo-default}"

# Pin the iOS min-version so rustc AND cc-rs (secp256k1 C) agree with the app's
# deployment target; otherwise the static lib objects link with a "built for newer
# iOS version" warning.
export IPHONEOS_DEPLOYMENT_TARGET="26.0"

echo "[ios] building arm64 device"
"$CARGO" build --release -p "$CRATE" --target aarch64-apple-ios

echo "[ios] building arm64 sim"
"$CARGO" build --release -p "$CRATE" --target aarch64-apple-ios-sim

echo "[ios] building x86_64 sim"
"$CARGO" build --release -p "$CRATE" --target x86_64-apple-ios

echo "[ios] creating universal simulator slice"
mkdir -p "target/universal-sim/$PROFILE_DIR"
lipo -create \
    "target/aarch64-apple-ios-sim/$PROFILE_DIR/$LIB.a" \
    "target/x86_64-apple-ios/$PROFILE_DIR/$LIB.a" \
    -output "target/universal-sim/$PROFILE_DIR/$LIB.a"

echo "[ios] generating Swift bindings"
rm -rf ios/bindings
mkdir -p ios/bindings
"$CARGO" run --release -p "$CRATE" --bin uniffi-bindgen -- \
    generate \
    --library "target/aarch64-apple-ios/$PROFILE_DIR/$LIB.a" \
    --language swift \
    --out-dir ios/bindings

# Swift 6 language mode rejects `public static let X: <non-Sendable>`
# because it can hold mutable state across actor boundaries. UniFFI
# 0.31.1's vtable pointer declarations trip this. Mark them
# `nonisolated(unsafe)` post-generation. The pointers are
# genuinely shared and read-only at runtime (they hold the foreign
# callback dispatch table), so the suppression is correct rather
# than a workaround.
SWIFT_BINDINGS="ios/bindings/ledger_sol_core.swift"
sed -i.bak \
    -e 's/^    static let vtable:/    nonisolated(unsafe) static let vtable:/' \
    -e 's/^    static let vtablePtr:/    nonisolated(unsafe) static let vtablePtr:/' \
    "$SWIFT_BINDINGS"
rm -f "${SWIFT_BINDINGS}.bak"

# When the xcframework wraps each slice in a `.framework` bundle, the
# module is identified by the framework name (LedgerSolCore), not the
# uniffi-generated module name (ledger_sol_coreFFI). Rewrite the
# import so the Swift binding pulls the FFI types from the framework
# module Xcode actually exposes.
sed -i.bak \
    -e 's/canImport(ledger_sol_coreFFI)/canImport(LedgerSolCore)/' \
    -e 's/import ledger_sol_coreFFI/import LedgerSolCore/' \
    "$SWIFT_BINDINGS"
rm -f "${SWIFT_BINDINGS}.bak"

# Wrap each static-library slice in a .framework bundle. Layout:
#   $FRAMEWORK.framework/
#     $FRAMEWORK              <- renamed libledger_sol_core.a
#     Headers/
#       <generated *.h>
#     Modules/
#       module.modulemap      <- namespaced under $FRAMEWORK so
#                               two uniffi xcframeworks don't both
#                               try to install to include/module.modulemap
#     Info.plist
make_framework_slice() {
    local STATIC_LIB="$1"
    local OUT_DIR="$2"
    local PLATFORM="$3"
    local FW_DIR="$OUT_DIR/$FRAMEWORK.framework"

    rm -rf "$FW_DIR"
    mkdir -p "$FW_DIR/Headers" "$FW_DIR/Modules"

    cp "$STATIC_LIB" "$FW_DIR/$FRAMEWORK"
    cp ios/bindings/*.h "$FW_DIR/Headers/"
    # Replace the uniffi-generated bare-module modulemap with a
    # `framework module` declaration named after the framework
    # bundle. Xcode resolves `import LedgerSolCore` against this.
    cat > "$FW_DIR/Modules/module.modulemap" <<MODMAP
framework module $FRAMEWORK {
    umbrella header "ledger_sol_coreFFI.h"
    export *
    module * { export * }
}
MODMAP

    cat > "$FW_DIR/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key><string>en</string>
    <key>CFBundleExecutable</key><string>$FRAMEWORK</string>
    <key>CFBundleIdentifier</key><string>com.elabify.$FRAMEWORK</string>
    <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
    <key>CFBundleName</key><string>$FRAMEWORK</string>
    <key>CFBundlePackageType</key><string>FMWK</string>
    <key>CFBundleShortVersionString</key><string>1.0</string>
    <key>CFBundleSignature</key><string>????</string>
    <key>CFBundleSupportedPlatforms</key>
    <array><string>$PLATFORM</string></array>
    <key>CFBundleVersion</key><string>1</string>
</dict>
</plist>
PLIST
}

echo "[ios] wrapping device slice as framework"
mkdir -p target/framework-device
make_framework_slice \
    "target/aarch64-apple-ios/$PROFILE_DIR/$LIB.a" \
    target/framework-device \
    iPhoneOS

echo "[ios] wrapping universal sim slice as framework"
mkdir -p target/framework-sim
make_framework_slice \
    "target/universal-sim/$PROFILE_DIR/$LIB.a" \
    target/framework-sim \
    iPhoneSimulator

echo "[ios] assembling xcframework"
rm -rf "ios/$FRAMEWORK.xcframework"
xcodebuild -create-xcframework \
    -framework "target/framework-device/$FRAMEWORK.framework" \
    -framework "target/framework-sim/$FRAMEWORK.framework" \
    -output "ios/$FRAMEWORK.xcframework"

echo "[ios] done: ios/$FRAMEWORK.xcframework"
echo "[ios] Swift glue: ios/bindings/*.swift"
