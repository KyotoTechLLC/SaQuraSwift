// Quantum.swift
// SaQura Swift Library
// Copyright (c) 2025-2026 KyotoTech LLC. All rights reserved.

import Foundation
import CryptoKit

/// Post-quantum cryptographic operations
/// Compatible with .NET SaQura Quantum encryption
public struct Quantum {
    // MARK: - Key Generation

    /// Generates a post-quantum key pair
    /// - Parameters:
    ///   - strength: Security level
    ///   - generation: Key generation algorithm version
    /// - Returns: Tuple containing (publicKey, privateKey) as byte arrays
    public static func generateKeyPair(
        strength: QuantumStrength,
        generation: QuantumGeneration
    ) async throws -> (publicKey: Data, privateKey: Data) {
        // Check license for restricted generations
        if !isDebugMode && !ApiLicense.isQuantumAvailable {
            if generation == .gen1 {
                throw LicenseException(
                    "Generation 1 is vulnerable to padding oracle attacks and requires a Pro license. " +
                    "Use Gen5 instead (secure replacement for Gen1) or purchase at \(ApiLicense.getLicensingPortalUrl())",
                    feature: .quantum
                )
            }

            if generation == .gen3 {
                throw LicenseException(
                    "Generation 3 has a critical XOR key-reuse vulnerability and requires a Pro license. " +
                    "Use Gen6 instead (secure mobile-optimized replacement) or purchase at \(ApiLicense.getLicensingPortalUrl())",
                    feature: .quantum
                )
            }

            if generation == .gen7 {
                throw LicenseException(
                    "Generation 7 (Hybrid RSA+Quantum) requires a Pro license due to its advanced features. " +
                    "Use Gen4 or Gen5 for quantum-safe encryption or purchase at \(ApiLicense.getLicensingPortalUrl())",
                    feature: .quantum
                )
            }

            InternalLogger.warning("Quantum key pair generated without license for \(generation) - encryption will be limited")
        }

        return try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    let keyPair = try generateKeyPairSync(strength: strength, generation: generation)
                    InternalLogger.debug("Generated \(generation) key pair: \(generation.securityAssessment)")
                    continuation.resume(returning: keyPair)
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    /// Synchronous key pair generation
    private static func generateKeyPairSync(
        strength: QuantumStrength,
        generation: QuantumGeneration
    ) throws -> (publicKey: Data, privateKey: Data) {
        switch generation {
        case .gen1:
            // Legacy Gen1 - for backward compatibility only
            return try QGeneration2.generateKeyPair(strength: strength)

        case .gen2:
            return try QGeneration2.generateKeyPair(strength: strength)

        case .gen3:
            // Legacy Gen3 - redirect to Gen6
            return try QGeneration6.generateKeyPair(strength: strength)

        case .gen4:
            return try QGeneration4.generateKeyPair(strength: strength)

        case .gen5:
            return try QGeneration5.generateKeyPair(strength: strength)

        case .gen6:
            return try QGeneration6.generateKeyPair(strength: strength)

        case .gen7:
            return try QGeneration7.generateKeyPair(strength: strength)
        }
    }

    // MARK: - Encryption

    /// Encrypts a message using post-quantum cryptography
    /// - Parameters:
    ///   - message: The message to encrypt
    ///   - publicKey: The public key
    /// - Returns: Tuple containing (encapsulatedSecret, encryptedMessage)
    public static func encrypt(
        _ message: String,
        publicKey: Data
    ) async throws -> (encapsulatedSecret: Data, encryptedMessage: Data) {
        // Check license for size limits
        if !isDebugMode && !ApiLicense.isQuantumAvailable {
            FeatureGate.applyRateLimitIfNeeded()

            let messageBytes = Data(message.utf8)
            if messageBytes.count > FeatureGate.unlicensedQuantumMaxSize {
                throw SaQuraError.sizeLimitExceeded(
                    limit: FeatureGate.unlicensedQuantumMaxSize,
                    actual: messageBytes.count,
                    feature: "Quantum"
                )
            }

            // Check for vulnerable generations
            if publicKey.count > 0 {
                let generation = QuantumGeneration(rawValue: publicKey[0])
                if generation == .gen1 || generation == .gen3 {
                    throw LicenseException(
                        "Vulnerable generation \(String(describing: generation)) requires a Pro license for security reasons.",
                        feature: .quantum
                    )
                }
            }
        }

        return try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    let result = try encryptSync(message, publicKey: publicKey)

                    // Apply watermark for unlicensed
                    var encryptedMessage = result.encryptedMessage
                    if !isDebugMode && !ApiLicense.isQuantumAvailable {
                        let watermarkBytes = Data(WatermarkHelper.unlicensedQuantumPrefix.utf8)
                        var watermarked = watermarkBytes
                        watermarked.append(encryptedMessage)
                        encryptedMessage = watermarked
                    }

                    continuation.resume(returning: (result.encapsulatedSecret, encryptedMessage))
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    /// Synchronous encryption
    private static func encryptSync(
        _ message: String,
        publicKey: Data
    ) throws -> (encapsulatedSecret: Data, encryptedMessage: Data) {
        guard publicKey.count >= 2 else {
            throw SaQuraError.invalidKey("Invalid quantum public key")
        }

        let generation = QuantumGeneration(rawValue: publicKey[0]) ?? .gen4

        switch generation {
        case .gen1, .gen2:
            return try QGeneration2.encrypt(message, publicKey: publicKey)
        case .gen3, .gen6:
            return try QGeneration6.encrypt(message, publicKey: publicKey)
        case .gen4:
            return try QGeneration4.encrypt(message, publicKey: publicKey)
        case .gen5:
            return try QGeneration5.encrypt(message, publicKey: publicKey)
        case .gen7:
            return try QGeneration7.encrypt(message, publicKey: publicKey)
        }
    }

    // MARK: - Decryption

    /// Decrypts a message using post-quantum cryptography
    /// - Parameters:
    ///   - encryptedMessage: The encrypted message
    ///   - privateKey: The private key
    ///   - secret: The encapsulated secret (optional for some generations)
    /// - Returns: Decrypted message
    public static func decrypt(
        _ encryptedMessage: Data,
        privateKey: Data,
        secret: Data? = nil
    ) async throws -> String {
        guard !encryptedMessage.isEmpty else { return "" }

        return try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    var actualMessage = encryptedMessage
                    var isWatermarked = false

                    // Check and remove watermark
                    let watermarkBytes = Data(WatermarkHelper.unlicensedQuantumPrefix.utf8)
                    if encryptedMessage.count > watermarkBytes.count {
                        if encryptedMessage.prefix(watermarkBytes.count) == watermarkBytes {
                            isWatermarked = true
                            actualMessage = Data(encryptedMessage.suffix(from: watermarkBytes.count))
                        }
                    }

                    // Check for vulnerable generations
                    if !isDebugMode && !ApiLicense.isQuantumAvailable && privateKey.count > 0 {
                        let generation = QuantumGeneration(rawValue: privateKey[0])
                        if generation == .gen1 || generation == .gen3 {
                            throw LicenseException(
                                "Decryption with vulnerable generation requires a Pro license.",
                                feature: .quantum
                            )
                        }
                    }

                    var decrypted = try decryptSync(actualMessage, privateKey: privateKey, secret: secret)

                    // Apply output watermark for unlicensed
                    if !isDebugMode && !ApiLicense.isQuantumAvailable {
                        FeatureGate.applyRateLimitIfNeeded()
                        decrypted = "\(WatermarkHelper.unlicensedQuantumPrefix) \(decrypted) \(WatermarkHelper.unlicensedQuantumSuffix)"
                    }

                    continuation.resume(returning: decrypted)
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    /// Synchronous decryption
    private static func decryptSync(
        _ encryptedMessage: Data,
        privateKey: Data,
        secret: Data?
    ) throws -> String {
        guard privateKey.count >= 2 else {
            throw SaQuraError.invalidKey("Invalid quantum private key")
        }

        let generation = QuantumGeneration(rawValue: privateKey[0]) ?? .gen4

        switch generation {
        case .gen1, .gen2:
            return try QGeneration2.decrypt(encryptedMessage, privateKey: privateKey, secret: secret)
        case .gen3, .gen6:
            return try QGeneration6.decrypt(encryptedMessage, privateKey: privateKey, secret: secret)
        case .gen4:
            return try QGeneration4.decrypt(encryptedMessage, privateKey: privateKey, secret: secret)
        case .gen5:
            return try QGeneration5.decrypt(encryptedMessage, privateKey: privateKey, secret: secret)
        case .gen7:
            return try QGeneration7.decrypt(encryptedMessage, privateKey: privateKey, secret: secret)
        }
    }

    // MARK: - Utility Functions

    /// Gets the recommended generation based on use case
    public static func getRecommendedGeneration(forMobile: Bool, highestSecurity: Bool) -> QuantumGeneration {
        if isDebugMode {
            return QuantumGeneration.recommended(forMobile: forMobile, highestSecurity: highestSecurity)
        }

        if !ApiLicense.isQuantumAvailable {
            // For unlicensed, recommend only secure generations
            return forMobile ? .gen6 : .gen4
        }

        return QuantumGeneration.recommended(forMobile: forMobile, highestSecurity: highestSecurity)
    }

    /// Validates if a generation is secure for production use
    public static func isSecureGeneration(_ generation: QuantumGeneration) -> Bool {
        return generation.isSecure
    }

    /// Gets security assessment for a generation
    public static func getSecurityAssessment(_ generation: QuantumGeneration) -> String {
        var assessment = generation.securityAssessment

        if !isDebugMode && !ApiLicense.isQuantumAvailable {
            if generation.requiresProLicense {
                assessment += " [REQUIRES PRO LICENSE]"
            } else {
                assessment += " [LIMITED TO \(FeatureGate.unlicensedQuantumMaxSize) BYTES WITHOUT LICENSE]"
            }
        }

        return assessment
    }
}
