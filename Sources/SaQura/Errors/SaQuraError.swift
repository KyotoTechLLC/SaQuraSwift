// SaQuraError.swift
// SaQura Swift Library
// Copyright (c) 2025-2026 KyotoTech LLC. All rights reserved.

import Foundation

/// Errors that can occur during cryptographic operations
public enum SaQuraError: LocalizedError {
    /// The provided encryption key is invalid or has wrong format
    case invalidKey(String)

    /// Encryption operation failed
    case encryptionFailed(String)

    /// Decryption operation failed (wrong key, corrupted data, or authentication failed)
    case decryptionFailed(String)

    /// A valid license is required for this feature
    case licenseRequired(feature: String, message: String)

    /// The cryptographic signature is invalid
    case signatureInvalid(String)

    /// The input data is invalid or malformed
    case invalidInput(String)

    /// The operation is not supported on this platform
    case platformNotSupported(String)

    /// Key generation failed
    case keyGenerationFailed(String)

    /// Password hashing failed
    case hashingFailed(String)

    /// License activation failed
    case licenseActivationFailed(String)

    /// License validation failed
    case licenseValidationFailed(String)

    /// Size limit exceeded (unlicensed usage)
    case sizeLimitExceeded(limit: Int, actual: Int, feature: String)

    /// Rate limit exceeded (unlicensed usage)
    case rateLimitExceeded(String)

    /// Quantum encryption error
    case quantumError(String)

    public var errorDescription: String? {
        switch self {
        case .invalidKey(let message):
            return "Invalid key: \(message)"
        case .encryptionFailed(let message):
            return "Encryption failed: \(message)"
        case .decryptionFailed(let message):
            return "Decryption failed: \(message)"
        case .licenseRequired(let feature, let message):
            return "License required for \(feature): \(message)"
        case .signatureInvalid(let message):
            return "Invalid signature: \(message)"
        case .invalidInput(let message):
            return "Invalid input: \(message)"
        case .platformNotSupported(let message):
            return "Platform not supported: \(message)"
        case .keyGenerationFailed(let message):
            return "Key generation failed: \(message)"
        case .hashingFailed(let message):
            return "Hashing failed: \(message)"
        case .licenseActivationFailed(let message):
            return "License activation failed: \(message)"
        case .licenseValidationFailed(let message):
            return "License validation failed: \(message)"
        case .sizeLimitExceeded(let limit, let actual, let feature):
            return "Size limit exceeded for \(feature): \(actual) bytes (limit: \(limit) bytes)"
        case .rateLimitExceeded(let message):
            return "Rate limit exceeded: \(message)"
        case .quantumError(let message):
            return "Quantum encryption error: \(message)"
        }
    }
}

/// Exception for license-related errors (mirrors .NET LicenseException)
public struct LicenseException: Error, LocalizedError {
    public let message: String
    public let feature: LicenseFeatures

    public init(_ message: String, feature: LicenseFeatures) {
        self.message = message
        self.feature = feature
    }

    public var errorDescription: String? {
        return message
    }
}
