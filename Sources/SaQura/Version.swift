// Version.swift
// SaQura Swift Library
// Copyright (c) 2025-2026 KyotoTech LLC. All rights reserved.

import Foundation

/// Public version string of the SaQura Swift library.
///
/// Bump on every release. Matches the git tag (without leading `v`).
/// Mirrors the .NET csproj `<Version>` and the Kotlin
/// `libs.versions.toml` `saqura` entry.
///
/// Used by the test-corpus generator script (`generate_swift.sh`) to
/// derive the `fixtures/swift_<version>/` output directory and by the
/// `FullCorpusGenerator` XCTest class to stamp the corpus manifest.
public let saquraVersion = "1.0.8"
