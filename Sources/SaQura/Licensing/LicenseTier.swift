// LicenseTier.swift
// SaQura Swift Library
// Copyright (c) 2025-2026 KyotoTech LLC. All rights reserved.

import Foundation

/// License tiers matching .NET SaQura
public enum LicenseTier: Int, Codable, CaseIterable, Sendable {
    case free = 0
    case basic = 1
    case standard = 2
    case pro = 3
    case enterprise = 4
    case `internal` = 99

    /// Display name for the tier
    public var displayName: String {
        switch self {
        case .free: return "Free"
        case .basic: return "Basic"
        case .standard: return "Standard"
        case .pro: return "Pro"
        case .enterprise: return "Enterprise"
        case .internal: return "Internal"
        }
    }

    /// License key prefix for this tier
    public var keyPrefix: String {
        switch self {
        case .free: return "FREE"
        case .basic: return "BAS"
        case .standard: return "STD"
        case .pro: return "PRO"
        case .enterprise: return "ENT"
        case .internal: return "INT"
        }
    }

    /// Creates tier from license key prefix
    public static func from(keyPrefix: String) -> LicenseTier? {
        let prefix = keyPrefix.uppercased()
        return LicenseTier.allCases.first { $0.keyPrefix == prefix }
    }
}
