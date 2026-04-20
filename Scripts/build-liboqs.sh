#!/bin/bash
# build-liboqs.sh
# Builds liboqs with only FrodoKEM + Classic McEliece for minimal binary size
# Produces liboqs.xcframework for iOS, iOS Simulator, and macOS
#
# Usage: ./Scripts/build-liboqs.sh
# Output: Libs/liboqs.xcframework
#
# Prerequisites: cmake, Xcode with iOS/macOS SDKs

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_DIR/build/liboqs-build"
LIBOQS_SRC="$BUILD_DIR/liboqs"
OUTPUT_DIR="$PROJECT_DIR/Libs"
LIBOQS_VERSION="0.12.0"
NPROC=$(sysctl -n hw.logicalcpu)

echo "=== Building liboqs $LIBOQS_VERSION for Apple platforms ==="
echo "Project: $PROJECT_DIR"
echo "Build:   $BUILD_DIR"
echo "Output:  $OUTPUT_DIR"
echo "Cores:   $NPROC"

# Clean previous build
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

# Clone liboqs
echo ""
echo "=== Cloning liboqs ==="
git clone --depth 1 --branch "$LIBOQS_VERSION" \
    https://github.com/open-quantum-safe/liboqs.git "$LIBOQS_SRC"

# Common CMake flags: only FrodoKEM + Classic McEliece
COMMON_CMAKE_FLAGS=(
    -DCMAKE_BUILD_TYPE=Release
    -DBUILD_SHARED_LIBS=OFF
    -DOQS_BUILD_ONLY_LIB=ON
    -DOQS_MINIMAL_BUILD="KEM_classic_mceliece_6688128;KEM_classic_mceliece_6960119;KEM_classic_mceliece_8192128;KEM_frodokem_640_aes;KEM_frodokem_976_aes;KEM_frodokem_1344_aes"
    -DOQS_USE_CPU_EXTENSIONS=OFF
    -DOQS_USE_OPENSSL=OFF
    -DOQS_DIST_BUILD=OFF
    -DOQS_USE_AES_INSTRUCTIONS=OFF
    -DOQS_USE_SHA2_INSTRUCTIONS=OFF
    -DOQS_USE_SHA3_INSTRUCTIONS=OFF
    -DOQS_OPT_TARGET=generic
)

build_platform() {
    local LABEL=$1
    local ARCH=$2
    local SYSROOT=$3
    local MIN_VERSION_FLAG=$4
    local CMAKE_SYS_NAME=$5
    local CMAKE_SYS_PROCESSOR=$6
    local BUILD_SUBDIR="$BUILD_DIR/$LABEL"

    echo ""
    echo "=== Building for $LABEL ($ARCH) ==="
    mkdir -p "$BUILD_SUBDIR"

    cmake -S "$LIBOQS_SRC" -B "$BUILD_SUBDIR" \
        "${COMMON_CMAKE_FLAGS[@]}" \
        -DCMAKE_SYSTEM_NAME="$CMAKE_SYS_NAME" \
        -DCMAKE_SYSTEM_PROCESSOR="$CMAKE_SYS_PROCESSOR" \
        -DCMAKE_OSX_ARCHITECTURES="$ARCH" \
        -DCMAKE_OSX_SYSROOT="$SYSROOT" \
        -DCMAKE_C_FLAGS="$MIN_VERSION_FLAG" \
        -DCMAKE_INSTALL_PREFIX="$BUILD_SUBDIR/install"

    cmake --build "$BUILD_SUBDIR" --config Release -- -j"$NPROC"
    cmake --install "$BUILD_SUBDIR" --config Release

    echo "=== $LABEL build complete ==="
}

IOS_SYSROOT="$(xcrun --sdk iphoneos --show-sdk-path)"
SIM_SYSROOT="$(xcrun --sdk iphonesimulator --show-sdk-path)"
MAC_SYSROOT="$(xcrun --sdk macosx --show-sdk-path)"

# Build for iOS device (arm64)
build_platform "ios-arm64" "arm64" \
    "$IOS_SYSROOT" \
    "-miphoneos-version-min=15.0" \
    "iOS" "aarch64"

# Build for iOS Simulator arm64
build_platform "iossim-arm64" "arm64" \
    "$SIM_SYSROOT" \
    "-mios-simulator-version-min=15.0 -target arm64-apple-ios15.0-simulator" \
    "iOS" "aarch64"

# Build for iOS Simulator x86_64
build_platform "iossim-x86_64" "x86_64" \
    "$SIM_SYSROOT" \
    "-mios-simulator-version-min=15.0 -target x86_64-apple-ios15.0-simulator" \
    "iOS" "x86_64"

# Build for macOS arm64
build_platform "macos-arm64" "arm64" \
    "$MAC_SYSROOT" \
    "-mmacosx-version-min=12.0" \
    "Darwin" "aarch64"

# Build for macOS x86_64
build_platform "macos-x86_64" "x86_64" \
    "$MAC_SYSROOT" \
    "-mmacosx-version-min=12.0" \
    "Darwin" "x86_64"

echo ""
echo "=== Creating fat libraries ==="

# iOS Simulator fat lib (arm64 + x86_64)
mkdir -p "$BUILD_DIR/iossim-universal/install/lib"
cp -r "$BUILD_DIR/iossim-arm64/install/include" "$BUILD_DIR/iossim-universal/install/"
lipo -create \
    "$BUILD_DIR/iossim-arm64/install/lib/liboqs.a" \
    "$BUILD_DIR/iossim-x86_64/install/lib/liboqs.a" \
    -output "$BUILD_DIR/iossim-universal/install/lib/liboqs.a"

# macOS fat lib (arm64 + x86_64)
mkdir -p "$BUILD_DIR/macos-universal/install/lib"
cp -r "$BUILD_DIR/macos-arm64/install/include" "$BUILD_DIR/macos-universal/install/"
lipo -create \
    "$BUILD_DIR/macos-arm64/install/lib/liboqs.a" \
    "$BUILD_DIR/macos-x86_64/install/lib/liboqs.a" \
    -output "$BUILD_DIR/macos-universal/install/lib/liboqs.a"

echo ""
echo "=== Creating XCFramework ==="

rm -rf "$OUTPUT_DIR/liboqs.xcframework"
mkdir -p "$OUTPUT_DIR"

xcodebuild -create-xcframework \
    -library "$BUILD_DIR/ios-arm64/install/lib/liboqs.a" \
    -headers "$BUILD_DIR/ios-arm64/install/include" \
    -library "$BUILD_DIR/iossim-universal/install/lib/liboqs.a" \
    -headers "$BUILD_DIR/iossim-universal/install/include" \
    -library "$BUILD_DIR/macos-universal/install/lib/liboqs.a" \
    -headers "$BUILD_DIR/macos-universal/install/include" \
    -output "$OUTPUT_DIR/liboqs.xcframework"

echo ""
echo "=== Build complete ==="
echo "XCFramework: $OUTPUT_DIR/liboqs.xcframework"
ls -la "$OUTPUT_DIR/liboqs.xcframework/"
echo ""
echo "To verify: file \"\$OUTPUT_DIR/liboqs.xcframework/*/liboqs.a\""
