// LicenseType.swift
// SaQura Swift Library
// Copyright (c) 2025-2026 KyotoTech LLC. All rights reserved.

import Foundation

/// License types (matches .NET SaQura)
public enum LicenseType: Int, Codable, Sendable {
    /// Standard license - hardware bound, limited activations
    case standard = 0

    /// Distribution license - no hardware binding, unlimited activations
    /// For embedding in distributed applications (App Store, Play Store)
    case distribution = 1
}
