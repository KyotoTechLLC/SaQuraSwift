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
                    // Output sanity-net (Defense-in-Depth, .NET 1.0.7 parity).
                    // The per-generation helpers should already throw on internal
                    // failure since v1.0.6, but this guards against future regressions
                    // where a backend silently returns an empty tuple.
                    try CallerInputValidator.ensureKeyGenOutput(keyPair, generation: generation, strength: strength)
                    InternalLogger.debug("Generated \(generation) key pair: \(generation.securityAssessment)")
                    continuation.resume(returning: keyPair)
                } catch let error as QuantumOperationError {
                    continuation.resume(throwing: error)
                } catch {
                    InternalLogger.warning("Quantum key generation failed for \(generation): \(error.localizedDescription)")
                    continuation.resume(throwing: QuantumOperationError.keyGeneration(
                        generation: generation,
                        strength: strength,
                        underlyingError: error
                    ))
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
        // Defense-in-Depth (.NET 1.0.7 parity): rejects empty AND all-zero
        // public keys at the API boundary. All-zero is the signal that the
        // caller defensively wiped a previously-cached key reference and is
        // now passing the cleared buffer back. Throws SaQuraError.invalidInput
        // BEFORE any async dispatch so it bubbles straight to the caller
        // without being wrapped in QuantumOperationError.
        try CallerInputValidator.ensurePublicKey(publicKey)

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

                    // Output sanity-net (Defense-in-Depth, .NET 1.0.7 parity).
                    // Helper-level v1.0.6 typed-error fix should already throw on
                    // internal failure; this guards future regressions that return
                    // empty tuples instead.
                    let keyGeneration = CallerInputValidator.generationFromKeyByte(publicKey)
                    let keyStrength = CallerInputValidator.strengthFromKeyByte(publicKey)
                    try CallerInputValidator.ensureEncryptOutput(
                        result.encapsulatedSecret,
                        memberName: "encapsulatedSecret",
                        generation: keyGeneration,
                        strength: keyStrength
                    )
                    try CallerInputValidator.ensureEncryptOutput(
                        result.encryptedMessage,
                        memberName: "encryptedMessage",
                        generation: keyGeneration,
                        strength: keyStrength
                    )

                    // Apply watermark for unlicensed
                    var encryptedMessage = result.encryptedMessage
                    if !isDebugMode && !ApiLicense.isQuantumAvailable {
                        let watermarkBytes = Data(WatermarkHelper.unlicensedQuantumPrefix.utf8)
                        var watermarked = watermarkBytes
                        watermarked.append(encryptedMessage)
                        encryptedMessage = watermarked
                    }

                    continuation.resume(returning: (result.encapsulatedSecret, encryptedMessage))
                } catch let error as QuantumOperationError {
                    continuation.resume(throwing: error)
                } catch {
                    let (gen, str) = detectGenerationAndStrength(from: publicKey)
                    InternalLogger.warning("Quantum encryption failed for \(gen): \(error.localizedDescription)")
                    continuation.resume(throwing: QuantumOperationError.encryption(
                        generation: gen,
                        strength: str,
                        underlyingError: error
                    ))
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

        // Defense-in-Depth (.NET 1.0.7 parity): rejects empty AND all-zero
        // key / secret buffers at the API boundary. Throws
        // SaQuraError.invalidInput BEFORE async dispatch so it bubbles
        // straight to the caller without QuantumOperationError wrapping.
        try CallerInputValidator.ensurePrivateKey(privateKey)
        if let secret = secret {
            try CallerInputValidator.ensureSecret(secret)
        }

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

                    // Output sanity-net (Defense-in-Depth, .NET 1.0.7 parity).
                    // Authentication failures legitimately return an empty string;
                    // a nil result would be a backend regression — wrap it in the
                    // typed Quantum error so callers catching QuantumOperationError
                    // still see it.
                    let keyGeneration = CallerInputValidator.generationFromKeyByte(privateKey)
                    let keyStrength = CallerInputValidator.strengthFromKeyByte(privateKey)
                    try CallerInputValidator.ensureDecryptOutput(
                        decrypted,
                        generation: keyGeneration,
                        strength: keyStrength
                    )

                    // Apply output watermark for unlicensed
                    if !isDebugMode && !ApiLicense.isQuantumAvailable {
                        FeatureGate.applyRateLimitIfNeeded()
                        decrypted = "\(WatermarkHelper.unlicensedQuantumPrefix) \(decrypted) \(WatermarkHelper.unlicensedQuantumSuffix)"
                    }

                    continuation.resume(returning: decrypted)
                } catch let error as QuantumOperationError {
                    continuation.resume(throwing: error)
                } catch {
                    let (gen, str) = detectGenerationAndStrength(from: privateKey)
                    InternalLogger.warning("Quantum decryption failed for \(gen): \(error.localizedDescription)")
                    continuation.resume(throwing: QuantumOperationError.decryption(
                        generation: gen,
                        strength: str,
                        underlyingError: error
                    ))
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

    // MARK: - Private helpers

    /// Reads the leading two metadata bytes (generation, strength) from a key blob.
    /// Falls back to (.gen4, .standard) when the blob is malformed — these are
    /// only used as diagnostic fields on the thrown error.
    private static func detectGenerationAndStrength(from key: Data) -> (QuantumGeneration, QuantumStrength) {
        let gen = QuantumGeneration(rawValue: key.first ?? 0) ?? .gen4
        let str: QuantumStrength = key.count >= 2
            ? (QuantumStrength(rawValue: key[key.startIndex + 1]) ?? .standard)
            : .standard
        return (gen, str)
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
