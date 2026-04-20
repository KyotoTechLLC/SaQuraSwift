// FeatureGate.swift
// SaQura Swift Library
// Copyright (c) 2025-2026 KyotoTech LLC. All rights reserved.

import Foundation

/// Controls feature access based on license status
internal enum FeatureGate {
    // Size limits for unlicensed usage (matches .NET)
    static let unlicensedAESMaxSize = 100
    static let unlicensedRSAMaxLength = 50
    static let unlicensedQuantumMaxSize = 80

    // Rate limiting
    private static var lastOperationTime: Date?
    private static let rateLimitDelay: TimeInterval = 0.5 // 500ms delay between operations
    private static let queue = DispatchQueue(label: "jp.kyototech.saqura.featuregate")

    /// Applies rate limiting for unlicensed usage
    static func applyRateLimitIfNeeded() {
        guard !isDebugMode && !ApiLicense.isLicensed else { return }

        queue.sync {
            if let lastTime = lastOperationTime {
                let elapsed = Date().timeIntervalSince(lastTime)
                if elapsed < rateLimitDelay {
                    Thread.sleep(forTimeInterval: rateLimitDelay - elapsed)
                }
            }
            lastOperationTime = Date()
        }
    }

    /// Checks if a feature requires a license
    static func requiresLicense(for feature: LicenseFeatures) -> Bool {
        switch feature {
        case .rsa:
            return false // RSA available in free mode with limits
        case .aes:
            return true  // Standard+ required
        case .quantum:
            return true  // Pro+ required
        case .passwordHashing:
            return false // Available with watermark
        case .noWatermark:
            return true  // Basic+ required
        default:
            return true
        }
    }

    /// Gets the minimum tier required for a feature
    static func minimumTier(for feature: LicenseFeatures) -> LicenseTier {
        switch feature {
        case .rsa, .passwordHashing:
            return .free
        case .noWatermark:
            return .basic
        case .aes:
            return .standard
        case .quantum:
            return .pro
        default:
            return .pro
        }
    }

    /// Checks if the current license allows a feature
    static func isFeatureAllowed(_ feature: LicenseFeatures) -> Bool {
        if isDebugMode { return true }

        switch feature {
        case .rsa:
            return true // Always allowed (with limits)
        case .passwordHashing:
            return true // Always allowed (with watermark)
        case .aes:
            return ApiLicense.isAESAvailable
        case .quantum:
            return ApiLicense.isQuantumAvailable
        case .noWatermark:
            return ApiLicense.isPasswordHashingAvailable
        default:
            return ApiLicense.isLicensed
        }
    }

    /// Throws error if feature is not allowed and exceeds free limits
    static func checkFeatureAccess(
        _ feature: LicenseFeatures,
        dataSize: Int? = nil,
        message: String? = nil
    ) throws {
        if isDebugMode { return }

        guard !isFeatureAllowed(feature) else { return }

        // Check size limits for features with free tier access
        if let size = dataSize {
            let limit: Int
            switch feature {
            case .aes:
                limit = unlicensedAESMaxSize
            case .rsa:
                limit = unlicensedRSAMaxLength
            case .quantum:
                limit = unlicensedQuantumMaxSize
            default:
                limit = Int.max
            }

            if size > limit {
                throw SaQuraError.sizeLimitExceeded(
                    limit: limit,
                    actual: size,
                    feature: String(describing: feature)
                )
            }
        }

        // Feature completely blocked
        if requiresLicense(for: feature) && !ApiLicense.isLicensed {
            let customMessage = message ?? "This feature requires a valid license."
            throw LicenseException(
                "\(customMessage) Purchase at \(ApiLicense.getLicensingPortalUrl())",
                feature: feature
            )
        }
    }
}
