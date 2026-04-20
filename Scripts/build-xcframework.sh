#!/bin/bash

# =============================================================================
# SaQura XCFramework Build Script
# KyotoTech LLC - 2026
# =============================================================================
#
# This script builds the SaQura library as an XCFramework for distribution.
# The XCFramework contains compiled binaries for all Apple platforms,
# hiding the source code from customers.
#
# Usage:
#   ./Scripts/build-xcframework.sh
#
# Output:
#   ./Distribution/SaQura.xcframework
#   ./Distribution/SaQura.xcframework.zip (for SPM binary target)
#
# Compatible with Swift 6+ / Xcode 16+ (no generate-xcodeproj needed).
#
# =============================================================================

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${PROJECT_DIR}/build"
DISTRIBUTION_DIR="${PROJECT_DIR}/Distribution"
FRAMEWORK_NAME="SaQura"
SCHEME_NAME="SaQura"

echo -e "${BLUE}=============================================${NC}"
echo -e "${BLUE}  SaQura XCFramework Build Script${NC}"
echo -e "${BLUE}  KyotoTech LLC${NC}"
echo -e "${BLUE}=============================================${NC}"
echo ""

# Navigate to project directory (required for xcodebuild to find Package.swift)
cd "$PROJECT_DIR"

# Clean previous builds
echo -e "${YELLOW}[1/7] Cleaning previous builds...${NC}"
rm -rf "$BUILD_DIR"
rm -rf "$DISTRIBUTION_DIR"
mkdir -p "$BUILD_DIR"
mkdir -p "$DISTRIBUTION_DIR"

# Resolve dependencies
echo -e "${YELLOW}[2/7] Resolving package dependencies...${NC}"
xcodebuild -resolvePackageDependencies \
    -scheme "$SCHEME_NAME" \
    -derivedDataPath "$BUILD_DIR/DerivedData" \
    -quiet 2>/dev/null || swift package resolve

# Build for iOS Device (arm64)
echo -e "${YELLOW}[3/7] Building for iOS Device (arm64)...${NC}"
xcodebuild archive \
    -scheme "$SCHEME_NAME" \
    -destination "generic/platform=iOS" \
    -archivePath "${BUILD_DIR}/${FRAMEWORK_NAME}-iOS" \
    -derivedDataPath "$BUILD_DIR/DerivedData" \
    -configuration Release \
    -skipPackagePluginValidation \
    SKIP_INSTALL=NO \
    BUILD_LIBRARY_FOR_DISTRIBUTION=NO \
    CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO CODE_SIGNING_ALLOWED=NO \
    -quiet

# Build for iOS Simulator (arm64 + x86_64)
echo -e "${YELLOW}[4/7] Building for iOS Simulator (arm64 + x86_64)...${NC}"
xcodebuild archive \
    -scheme "$SCHEME_NAME" \
    -destination "generic/platform=iOS Simulator" \
    -archivePath "${BUILD_DIR}/${FRAMEWORK_NAME}-iOS-Simulator" \
    -derivedDataPath "$BUILD_DIR/DerivedData" \
    -configuration Release \
    -skipPackagePluginValidation \
    SKIP_INSTALL=NO \
    BUILD_LIBRARY_FOR_DISTRIBUTION=NO \
    CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO CODE_SIGNING_ALLOWED=NO \
    -quiet

# Build for macOS (arm64 + x86_64)
echo -e "${YELLOW}[5/7] Building for macOS (arm64 + x86_64)...${NC}"
xcodebuild archive \
    -scheme "$SCHEME_NAME" \
    -destination "generic/platform=macOS" \
    -archivePath "${BUILD_DIR}/${FRAMEWORK_NAME}-macOS" \
    -derivedDataPath "$BUILD_DIR/DerivedData" \
    -configuration Release \
    -skipPackagePluginValidation \
    SKIP_INSTALL=NO \
    BUILD_LIBRARY_FOR_DISTRIBUTION=NO \
    CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO CODE_SIGNING_ALLOWED=NO \
    -quiet

# Build for tvOS (optional — skipped if SDK not installed)
echo -e "${YELLOW}[6/7] Building for tvOS...${NC}"
xcodebuild archive \
    -scheme "$SCHEME_NAME" \
    -destination "generic/platform=tvOS" \
    -archivePath "${BUILD_DIR}/${FRAMEWORK_NAME}-tvOS" \
    -derivedDataPath "$BUILD_DIR/DerivedData" \
    -configuration Release \
    -skipPackagePluginValidation \
    SKIP_INSTALL=NO \
    BUILD_LIBRARY_FOR_DISTRIBUTION=NO \
    CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO CODE_SIGNING_ALLOWED=NO \
    -quiet 2>&1 || echo -e "  ${YELLOW}Skipped tvOS (SDK not installed)${NC}"

xcodebuild archive \
    -scheme "$SCHEME_NAME" \
    -destination "generic/platform=tvOS Simulator" \
    -archivePath "${BUILD_DIR}/${FRAMEWORK_NAME}-tvOS-Simulator" \
    -derivedDataPath "$BUILD_DIR/DerivedData" \
    -configuration Release \
    -skipPackagePluginValidation \
    SKIP_INSTALL=NO \
    BUILD_LIBRARY_FOR_DISTRIBUTION=NO \
    CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO CODE_SIGNING_ALLOWED=NO \
    -quiet 2>&1 || echo -e "  ${YELLOW}Skipped tvOS Simulator (SDK not installed)${NC}"

# Build for watchOS (optional — skipped if SDK not installed)
echo -e "${YELLOW}[7/7] Building for watchOS...${NC}"
xcodebuild archive \
    -scheme "$SCHEME_NAME" \
    -destination "generic/platform=watchOS" \
    -archivePath "${BUILD_DIR}/${FRAMEWORK_NAME}-watchOS" \
    -derivedDataPath "$BUILD_DIR/DerivedData" \
    -configuration Release \
    -skipPackagePluginValidation \
    SKIP_INSTALL=NO \
    BUILD_LIBRARY_FOR_DISTRIBUTION=NO \
    CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO CODE_SIGNING_ALLOWED=NO \
    -quiet 2>&1 || echo -e "  ${YELLOW}Skipped watchOS (SDK not installed)${NC}"

xcodebuild archive \
    -scheme "$SCHEME_NAME" \
    -destination "generic/platform=watchOS Simulator" \
    -archivePath "${BUILD_DIR}/${FRAMEWORK_NAME}-watchOS-Simulator" \
    -derivedDataPath "$BUILD_DIR/DerivedData" \
    -configuration Release \
    -skipPackagePluginValidation \
    SKIP_INSTALL=NO \
    BUILD_LIBRARY_FOR_DISTRIBUTION=NO \
    CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO CODE_SIGNING_ALLOWED=NO \
    -quiet 2>&1 || echo -e "  ${YELLOW}Skipped watchOS Simulator (SDK not installed)${NC}"

# Create XCFramework
echo -e "${YELLOW}Creating XCFramework...${NC}"

# Collect available framework paths from archives
XCFRAMEWORK_ARGS=()
ARCHIVES=(
    "${FRAMEWORK_NAME}-iOS"
    "${FRAMEWORK_NAME}-iOS-Simulator"
    "${FRAMEWORK_NAME}-macOS"
    "${FRAMEWORK_NAME}-tvOS"
    "${FRAMEWORK_NAME}-tvOS-Simulator"
    "${FRAMEWORK_NAME}-watchOS"
    "${FRAMEWORK_NAME}-watchOS-Simulator"
)

for ARCHIVE in "${ARCHIVES[@]}"; do
    # Dynamic libraries from SPM install to usr/local/lib/ instead of Library/Frameworks/
    FRAMEWORK_PATH="${BUILD_DIR}/${ARCHIVE}.xcarchive/Products/usr/local/lib/${FRAMEWORK_NAME}.framework"
    if [ ! -d "$FRAMEWORK_PATH" ]; then
        # Fallback: check Library/Frameworks/ (Xcode project default)
        FRAMEWORK_PATH="${BUILD_DIR}/${ARCHIVE}.xcarchive/Products/Library/Frameworks/${FRAMEWORK_NAME}.framework"
    fi
    if [ -d "$FRAMEWORK_PATH" ]; then
        XCFRAMEWORK_ARGS+=(-framework "$FRAMEWORK_PATH")
        echo -e "  ${GREEN}Found: ${ARCHIVE}${NC}"
    else
        echo -e "  ${YELLOW}Skipped (not found): ${ARCHIVE}${NC}"
    fi
done

if [ ${#XCFRAMEWORK_ARGS[@]} -eq 0 ]; then
    echo -e "${RED}ERROR: No archives produced any frameworks.${NC}"
    exit 1
fi

xcodebuild -create-xcframework \
    "${XCFRAMEWORK_ARGS[@]}" \
    -output "${DISTRIBUTION_DIR}/${FRAMEWORK_NAME}.xcframework"

# Create ZIP for Swift Package Manager binary target
echo -e "${YELLOW}Creating ZIP archive for SPM...${NC}"
cd "$DISTRIBUTION_DIR"
zip -r -q "${FRAMEWORK_NAME}.xcframework.zip" "${FRAMEWORK_NAME}.xcframework"

# Calculate checksum for Package.swift
CHECKSUM=$(shasum -a 256 "${FRAMEWORK_NAME}.xcframework.zip" | awk '{print $1}')

echo ""
echo -e "${GREEN}=============================================${NC}"
echo -e "${GREEN}  Build Complete!${NC}"
echo -e "${GREEN}=============================================${NC}"
echo ""
echo -e "XCFramework: ${BLUE}${DISTRIBUTION_DIR}/${FRAMEWORK_NAME}.xcframework${NC}"
echo -e "ZIP Archive: ${BLUE}${DISTRIBUTION_DIR}/${FRAMEWORK_NAME}.xcframework.zip${NC}"
echo ""
echo -e "${YELLOW}SHA256 Checksum for Package.swift:${NC}"
echo -e "${GREEN}${CHECKSUM}${NC}"
echo ""
echo -e "Add this to your distribution Package.swift:"
echo ""
echo -e "${BLUE}.binaryTarget(${NC}"
echo -e "${BLUE}    name: \"SaQura\",${NC}"
echo -e "${BLUE}    url: \"https://github.com/kyototech/SaQuraSwift/releases/download/VERSION/SaQura.xcframework.zip\",${NC}"
echo -e "${BLUE}    checksum: \"${CHECKSUM}\"${NC}"
echo -e "${BLUE})${NC}"
echo ""

# Save checksum to file
echo "$CHECKSUM" > "${DISTRIBUTION_DIR}/checksum.txt"

echo -e "${GREEN}Done!${NC}"
