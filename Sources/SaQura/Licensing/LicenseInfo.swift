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

    /// Effective feature set: explicit `features` bits if non-zero,
    /// otherwise derived from `tier` (matches .NET `LicensingService.EnabledFeatures`
    /// and Kotlin `LicenseInfo.effectiveFeatures`).
    public var effectiveFeatures: LicenseFeatures {
        return features.rawValue != 0 ? features : LicenseFeatures.features(for: tier)
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

    // MARK: - Memberwise initialiser
    //
    // The memberwise init is preserved explicitly so callers (and our
    // own LicenseValidator tests) can build LicenseInfo instances by
    // hand without going through Codable.

    public init(
        id: UUID,
        licenseKey: String,
        product: String,
        tier: LicenseTier,
        type: LicenseType,
        parentLicenseId: UUID?,
        features: LicenseFeatures,
        customer: CustomerInfo,
        issuedAt: Date,
        expiresAt: Date,
        hardwareId: String?,
        maxActivations: Int,
        currentActivations: Int,
        isRevoked: Bool,
        signature: String,
        metadata: [String: String]?,
        lastValidated: Date? = nil,
        serverValidated: Bool = false,
        registeredHardwareId: String? = nil,
        issuedAtRaw: String? = nil,
        expiresAtRaw: String? = nil
    ) {
        self.id = id
        self.licenseKey = licenseKey
        self.product = product
        self.tier = tier
        self.type = type
        self.parentLicenseId = parentLicenseId
        self.features = features
        self.customer = customer
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
        self.hardwareId = hardwareId
        self.maxActivations = maxActivations
        self.currentActivations = currentActivations
        self.isRevoked = isRevoked
        self.signature = signature
        self.metadata = metadata
        self.lastValidated = lastValidated
        self.serverValidated = serverValidated
        self.registeredHardwareId = registeredHardwareId
        self.issuedAtRaw = issuedAtRaw
        self.expiresAtRaw = expiresAtRaw
    }

    // MARK: - Codable
    //
    // **Bug history.** The synthesised Codable init treated
    // `serverValidated: Bool` as a non-optional required field — but the
    // production .NET license server NEVER includes this property in
    // emitted `.lic` files (it's an internal flag set on the consumer
    // side after activation). Decoding any real `.lic` therefore failed
    // with `keyNotFound("serverValidated")`, which `deserializeLicense`
    // swallowed and surfaced as a silent nil return. The bug was
    // undetected because the Swift library had no License-system tests
    // until the 2026-05-12 test sweep.
    //
    // We now decode every nominally-optional field with `decodeIfPresent`
    // and supply the .NET-canonical defaults for missing keys.

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.id = try c.decode(UUID.self, forKey: .id)
        self.licenseKey = try c.decodeIfPresent(String.self, forKey: .licenseKey) ?? ""
        self.product = try c.decodeIfPresent(String.self, forKey: .product) ?? "SaQura"
        self.tier = try c.decode(LicenseTier.self, forKey: .tier)
        // .NET default for missing/null `type` is Standard (0).
        self.type = try c.decodeIfPresent(LicenseType.self, forKey: .type) ?? .standard
        self.parentLicenseId = try c.decodeIfPresent(UUID.self, forKey: .parentLicenseId)
        self.features = try c.decodeIfPresent(LicenseFeatures.self, forKey: .features) ?? .none
        self.customer = try c.decode(CustomerInfo.self, forKey: .customer)
        self.issuedAt = try c.decode(Date.self, forKey: .issuedAt)
        self.expiresAt = try c.decode(Date.self, forKey: .expiresAt)
        self.hardwareId = try c.decodeIfPresent(String.self, forKey: .hardwareId)
        self.maxActivations = try c.decodeIfPresent(Int.self, forKey: .maxActivations) ?? 1
        self.currentActivations = try c.decodeIfPresent(Int.self, forKey: .currentActivations) ?? 0
        self.isRevoked = try c.decodeIfPresent(Bool.self, forKey: .isRevoked) ?? false
        self.signature = try c.decodeIfPresent(String.self, forKey: .signature) ?? ""
        self.metadata = try c.decodeIfPresent([String: String].self, forKey: .metadata)
        self.lastValidated = try c.decodeIfPresent(Date.self, forKey: .lastValidated)
        self.serverValidated = try c.decodeIfPresent(Bool.self, forKey: .serverValidated) ?? false
        self.registeredHardwareId = try c.decodeIfPresent(String.self, forKey: .registeredHardwareId)
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(id, forKey: .id)
        try c.encode(licenseKey, forKey: .licenseKey)
        try c.encode(product, forKey: .product)
        try c.encode(tier, forKey: .tier)
        try c.encode(type, forKey: .type)
        try c.encodeIfPresent(parentLicenseId, forKey: .parentLicenseId)
        try c.encode(features, forKey: .features)
        try c.encode(customer, forKey: .customer)
        try c.encode(issuedAt, forKey: .issuedAt)
        try c.encode(expiresAt, forKey: .expiresAt)
        try c.encodeIfPresent(hardwareId, forKey: .hardwareId)
        try c.encode(maxActivations, forKey: .maxActivations)
        try c.encode(currentActivations, forKey: .currentActivations)
        try c.encode(isRevoked, forKey: .isRevoked)
        try c.encode(signature, forKey: .signature)
        try c.encodeIfPresent(metadata, forKey: .metadata)
        try c.encodeIfPresent(lastValidated, forKey: .lastValidated)
        try c.encode(serverValidated, forKey: .serverValidated)
        try c.encodeIfPresent(registeredHardwareId, forKey: .registeredHardwareId)
    }
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
