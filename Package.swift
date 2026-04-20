// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

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
            type: .dynamic,
            targets: ["SaQura"]
        ),
    ],
    dependencies: [],
    targets: [
        // Pre-built liboqs binary (FrodoKEM + Classic McEliece)
        .binaryTarget(
            name: "liboqs",
            path: "Libs/liboqs.xcframework"
        ),
        // C interop module for liboqs
        .target(
            name: "CLibOQS",
            dependencies: ["liboqs"],
            path: "Sources/CLibOQS",
            publicHeadersPath: "include"
        ),
        .target(
            name: "SaQura",
            dependencies: ["CLibOQS"],
            path: "Sources/SaQura",
            swiftSettings: [
                .define("DEBUG", .when(configuration: .debug))
            ]
        ),
        .testTarget(
            name: "SaQuraTests",
            dependencies: ["SaQura"],
            path: "Tests/SaQuraTests"
        ),
    ]
)
