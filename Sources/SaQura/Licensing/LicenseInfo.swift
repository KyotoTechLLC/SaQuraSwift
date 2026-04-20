// LicenseInfo.swift
// SaQura Swift Library
// Copyright (c) 2025-2026 KyotoTech LLC. All rights reserved.

import Foundation

/// Complete license information (matches .NET SaQura)
public struct LicenseInfo: Codable, Sendable {
    /// Unique license identifier
    public let id: UUID

    /// License key in format TIER-XXXX-XXXX-XXXX-XXXX
    public let licenseKey: String

    /// Product name
    public let product: String

    /// License tier
    public let tier: LicenseTier

    /// License type (Standard or Distribution)
    public let type: LicenseType

    /// Parent license ID (for distribution licenses)
    public let parentLicenseId: UUID?

    /// Enabled features
    public let features: LicenseFeatures

    /// Customer information
    public let customer: CustomerInfo

    /// Issue date (UTC)
    public let issuedAt: Date

    /// Expiration date (UTC)
    public let expiresAt: Date

    /// Hardware ID this license is bound to
    public let hardwareId: String?

    /// Maximum number of activations allowed
    public let maxActivations: Int

    /// Current activation count
    public let currentActivations: Int

    /// Whether the license has been revoked
    public let isRevoked: Bool

    /// RSA signature for validation
    public let signature: String

    /// Additional metadata
    public let metadata: [String: String]?

    /// Last validation timestamp (UTC)
    public var lastValidated: Date?

    /// Whether this license has been validated with the server
    public var serverValidated: Bool

    /// Hardware ID registered with the server
    public var registeredHardwareId: String?

    // MARK: - Computed Properties

    /// Checks if the license is currently valid
    public var isValid: Bool {
        return !isRevoked &&
               Date() >= issuedAt &&
               Date() <= expiresAt
    }

    /// Days until expiration
    public var daysUntilExpiration: Int {
        guard isValid else { return 0 }
        return Calendar.current.dateComponents([.day], from: Date(), to: expiresAt).day ?? 0
    }

    /// Checks if license needs renewal (less than 30 days)
    public var needsRenewal: Bool {
        return daysUntilExpiration > 0 && daysUntilExpiration <= 30
    }

    // MARK: - Coding Keys

    enum CodingKeys: String, CodingKey {
        case id
        case licenseKey
        case product
        case tier
        case type
        case parentLicenseId
        case features
        case customer
        case issuedAt
        case expiresAt
        case hardwareId
        case maxActivations
        case currentActivations
        case isRevoked
        case signature
        case metadata
        case lastValidated
        case serverValidated
        case registeredHardwareId
    }

    // MARK: - Internal Properties (for signature verification)

    /// Raw issuedAt string from JSON (for signature verification)
    internal var issuedAtRaw: String?

    /// Raw expiresAt string from JSON (for signature verification)
    internal var expiresAtRaw: String?
}

/// Customer information for a license
public struct CustomerInfo: Codable, Sendable {
    /// Customer unique identifier
    public let id: UUID

    /// Customer email address
    public let email: String

    /// Company name
    public let company: String?

    /// Customer name
    public let name: String?

    enum CodingKeys: String, CodingKey {
        case id
        case email
        case company
        case name
    }
}

/// Result of license activation
public struct ActivationResult: Sendable {
    public let success: Bool
    public let message: String?
    public let errorMessage: String?
    public let license: LicenseInfo?

    public init(success: Bool, message: String? = nil, errorMessage: String? = nil, license: LicenseInfo? = nil) {
        self.success = success
        self.message = message
        self.errorMessage = errorMessage
        self.license = license
    }
}

/// Result of license validation
public struct ValidationResult: Sendable {
    public let isValid: Bool
    public let errorMessage: String?
    public let warning: String?
    public let features: LicenseFeatures
    public let tier: LicenseTier
    public let daysRemaining: Int
    public let isExpired: Bool
    public let hardwareMismatch: Bool
    public let isDistributionLicense: Bool

    public init(
        isValid: Bool = false,
        errorMessage: String? = nil,
        warning: String? = nil,
        features: LicenseFeatures = .none,
        tier: LicenseTier = .free,
        daysRemaining: Int = 0,
        isExpired: Bool = false,
        hardwareMismatch: Bool = false,
        isDistributionLicense: Bool = false
    ) {
        self.isValid = isValid
        self.errorMessage = errorMessage
        self.warning = warning
        self.features = features
        self.tier = tier
        self.daysRemaining = daysRemaining
        self.isExpired = isExpired
        self.hardwareMismatch = hardwareMismatch
        self.isDistributionLicense = isDistributionLicense
    }
}
