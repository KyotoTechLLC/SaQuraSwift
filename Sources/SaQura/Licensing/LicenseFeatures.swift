// LicenseFeatures.swift
// SaQura Swift Library
// Copyright (c) 2025-2026 KyotoTech LLC. All rights reserved.

import Foundation

/// License features as bit flags (matches .NET SaQura)
public struct LicenseFeatures: OptionSet, Codable, Sendable {
    public let rawValue: Int

    public init(rawValue: Int) {
        self.rawValue = rawValue
    }

    /// RSA encryption/decryption
    public static let rsa = LicenseFeatures(rawValue: 1 << 0)

    /// AES encryption/decryption
    public static let aes = LicenseFeatures(rawValue: 1 << 1)

    /// Quantum-safe encryption
    public static let quantum = LicenseFeatures(rawValue: 1 << 2)

    /// Password hashing without watermark
    public static let passwordHashing = LicenseFeatures(rawValue: 1 << 3)

    /// No watermark on output
    public static let noWatermark = LicenseFeatures(rawValue: 1 << 4)

    /// Priority support
    public static let prioritySupport = LicenseFeatures(rawValue: 1 << 5)

    /// All features enabled
    public static let all: LicenseFeatures = [.rsa, .aes, .quantum, .passwordHashing, .noWatermark, .prioritySupport]

    /// No features enabled
    public static let none = LicenseFeatures(rawValue: 0)

    /// Basic tier features
    public static let basic: LicenseFeatures = [.rsa, .passwordHashing, .noWatermark]

    /// Standard tier features
    public static let standard: LicenseFeatures = [.rsa, .aes, .passwordHashing, .noWatermark]

    /// Pro tier features
    public static let pro: LicenseFeatures = [.rsa, .aes, .quantum, .passwordHashing, .noWatermark]

    /// Enterprise tier features
    public static let enterprise: LicenseFeatures = .all

    /// Features for a specific tier
    public static func features(for tier: LicenseTier) -> LicenseFeatures {
        switch tier {
        case .free:
            return .none
        case .basic:
            return .basic
        case .standard:
            return .standard
        case .pro:
            return .pro
        case .enterprise, .internal:
            return .all
        }
    }
}
