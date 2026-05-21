#!/bin/bash

# =============================================================================
# SaQura Distribution Package Creator
# KyotoTech LLC - 2026
# =============================================================================
#
# This script creates a complete distribution package ready for publishing.
# It builds the XCFramework and prepares all files for a public repository.
#
# Usage:
#   ./Scripts/create-distribution.sh [version]
#
# Example:
#   ./Scripts/create-distribution.sh 1.0.0
#
# Output:
#   ./Distribution/
#   ├── SaQura.xcframework/
#   ├── SaQura.xcframework.zip
#   ├── Package.swift
#   ├── README.md
#   ├── USER_GUIDE.md
#   └── checksum.txt
#
# =============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DISTRIBUTION_DIR="${PROJECT_DIR}/Distribution"
VERSION="${1:-1.0.0}"

echo -e "${BLUE}=============================================${NC}"
echo -e "${BLUE}  SaQura Distribution Package Creator${NC}"
echo -e "${BLUE}  Version: ${VERSION}${NC}"
echo -e "${BLUE}=============================================${NC}"
echo ""

# Step 1: Build XCFramework
echo -e "${YELLOW}[1/4] Building XCFramework...${NC}"
"${SCRIPT_DIR}/build-xcframework.sh"

# Step 2: Read checksum
CHECKSUM=$(cat "${DISTRIBUTION_DIR}/checksum.txt")
echo -e "${GREEN}Checksum: ${CHECKSUM}${NC}"

# Step 3: Create Package.swift with correct checksum
echo -e "${YELLOW}[2/4] Creating Package.swift...${NC}"
cat > "${DISTRIBUTION_DIR}/Package.swift" << EOF
// swift-tools-version: 5.9
// SaQura Swift Library
// Copyright (c) 2025-2026 KyotoTech LLC. All rights reserved.

import PackageDescription

let package = Package(
    name: "SaQura",
    platforms: [
        .iOS(.v15),
        .macOS(.v12),
        .tvOS(.v15),
        .watchOS(.v8)
    ],
    products: [
        .library(
            name: "SaQura",
            targets: ["SaQura"]
        )
    ],
    targets: [
        .binaryTarget(
            name: "SaQura",
            url: "https://github.com/kyototech/SaQuraSwift/releases/download/${VERSION}/SaQura.xcframework.zip",
            checksum: "${CHECKSUM}"
        )
    ]
)
EOF

# Step 4: Copy documentation
echo -e "${YELLOW}[3/4] Copying documentation...${NC}"
cp "${PROJECT_DIR}/README.md" "${DISTRIBUTION_DIR}/"
cp "${PROJECT_DIR}/USER_GUIDE.md" "${DISTRIBUTION_DIR}/"

# Create a minimal LICENSE file
cat > "${DISTRIBUTION_DIR}/LICENSE" << 'EOF'
SaQura Swift Library
Copyright (c) 2025-2026 KyotoTech LLC. All rights reserved.

COMMERCIAL LICENSE

This software requires a commercial license for production use.
Free tier available for evaluation and development.

Purchase: https://kyototech.co.jp/pricing
Support: https://kyototech.co.jp/contact
Licensing Portal: https://billing.kyototech.co.jp

By using this software, you agree to the terms and conditions
available at https://kyototech.co.jp/terms
EOF

# Step 5: Create version file
echo -e "${YELLOW}[4/4] Creating version info...${NC}"
cat > "${DISTRIBUTION_DIR}/VERSION" << EOF
SaQura Swift
Version: ${VERSION}
Build Date: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
Checksum: ${CHECKSUM}
EOF

echo ""
echo -e "${GREEN}=============================================${NC}"
echo -e "${GREEN}  Distribution Package Created!${NC}"
echo -e "${GREEN}=============================================${NC}"
echo ""
echo -e "Location: ${BLUE}${DISTRIBUTION_DIR}${NC}"
echo ""
echo -e "Contents:"
ls -la "${DISTRIBUTION_DIR}"
echo ""
echo -e "${YELLOW}Next Steps:${NC}"
echo -e "1. Create a new GitHub repository: ${BLUE}kyototech/SaQuraSwift${NC}"
echo -e "2. Copy the contents of ${BLUE}Distribution/${NC} to the new repo"
echo -e "3. Create a GitHub Release with tag ${BLUE}${VERSION}${NC}"
echo -e "4. Upload ${BLUE}SaQura.xcframework.zip${NC} to the release"
echo -e "5. Customers can now add the package via SPM"
echo ""
echo -e "${GREEN}Done!${NC}"
