// RSAExtensions.swift
// SaQura Swift Library
// Copyright (c) 2025-2026 KyotoTech LLC. All rights reserved.

import Foundation

// MARK: - String Extensions for RSA

public extension String {
    /// Encrypts string using RSA or hybrid encryption (auto-selected based on size)
    /// - Parameter publicKey: RSA public key in PEM format
    /// - Returns: Base64-encoded encrypted data
    func encryptWithRSA(publicKey: String) async throws -> String {
        // Check license for length limits
        if !isDebugMode && !ApiLicense.isRSAAvailable {
            FeatureGate.applyRateLimitIfNeeded()

            if self.count > FeatureGate.unlicensedRSAMaxLength {
                throw LicenseException(
                    "Unlicensed RSA encryption is limited to \(FeatureGate.unlicensedRSAMaxLength) characters. " +
                    "Your input: \(self.count) characters. " +
                    "Purchase a license at \(ApiLicense.getLicensingPortalUrl()) for unlimited usage.",
                    feature: .rsa
                )
            }

            InternalLogger.debug("Unlicensed RSA encryption: \(self.count)/\(FeatureGate.unlicensedRSAMaxLength) characters")
        }

        return try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    let encrypted = try RSACryptographyHelper.encrypt(self, publicKey: publicKey)
                    continuation.resume(returning: encrypted)
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    /// Decrypts Base64-encoded RSA or hybrid encrypted data
    /// - Parameter privateKey: RSA private key in PEM format
    /// - Returns: Decrypted string
    func decryptWithRSA(privateKey: String) async throws -> String {
        return try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    var decrypted = try RSACryptographyHelper.decrypt(self, privateKey: privateKey)

                    // Add watermark for unlicensed
                    if !isDebugMode && !ApiLicense.isRSAAvailable {
                        FeatureGate.applyRateLimitIfNeeded()
                        decrypted = "\(WatermarkHelper.unlicensedRSAPrefix) \(decrypted) \(WatermarkHelper.unlicensedRSASuffix)"
                        InternalLogger.warning("Adding watermark to decrypted RSA output (unlicensed mode)")
                    }

                    continuation.resume(returning: decrypted)
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    /// Signs string using RSA-PSS with SHA256
    /// - Parameter privateKey: RSA private key in PEM format
    /// - Returns: Base64-encoded signature
    func signWithRSA(privateKey: String) async throws -> String {
        // Check license for length limits
        if !isDebugMode && !ApiLicense.isRSAAvailable {
            FeatureGate.applyRateLimitIfNeeded()

            if self.count > FeatureGate.unlicensedRSAMaxLength {
                throw LicenseException(
                    "Unlicensed RSA signing is limited to \(FeatureGate.unlicensedRSAMaxLength) characters. " +
                    "Purchase a license at \(ApiLicense.getLicensingPortalUrl())",
                    feature: .rsa
                )
            }
        }

        return try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    let data = Data(self.utf8)
                    let signature = try RSACryptographyHelper.sign(data, privateKeyPEM: privateKey)
                    continuation.resume(returning: signature.toBase64())
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    /// Verifies RSA-PSS signature
    /// - Parameters:
    ///   - signature: Base64-encoded signature
    ///   - publicKey: RSA public key in PEM format
    /// - Returns: True if signature is valid
    func verifyRSASignature(signature: String, publicKey: String) async throws -> Bool {
        return try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    let data = Data(self.utf8)
                    guard let signatureData = Data(base64Encoded: signature) else {
                        continuation.resume(returning: false)
                        return
                    }
                    let result = try RSACryptographyHelper.verifySignature(data, signature: signatureData, publicKeyPEM: publicKey)
                    continuation.resume(returning: result)
                } catch {
                    continuation.resume(returning: false)
                }
            }
        }
    }

    /// Validates if this string is a valid RSA private key
    func isValidRSAPrivateKey() async -> Bool {
        return RSAKey.isValidPrivateKey(self)
    }

    /// Validates if this string is a valid RSA public key
    func isValidRSAPublicKey() async -> Bool {
        return RSAKey.isValidPublicKey(self)
    }

    /// Extracts public key from this private key
    func getPublicKeyFromPrivateKey() async throws -> String {
        return try RSAKey.getPublicKey(from: self)
    }
}

// MARK: - Data Extensions for RSA

public extension Data {
    /// Encrypts data using RSA or hybrid encryption
    /// - Parameter publicKey: RSA public key as Data
    /// - Returns: Encrypted data
    func encryptWithRSA(publicKey: Data) async throws -> Data {
        // Check license for size limits
        if !isDebugMode && !ApiLicense.isRSAAvailable {
            FeatureGate.applyRateLimitIfNeeded()

            if self.count > FeatureGate.unlicensedRSAMaxLength {
                throw LicenseException(
                    "Unlicensed RSA encryption is limited to \(FeatureGate.unlicensedRSAMaxLength) bytes. " +
                    "Purchase a license at \(ApiLicense.getLicensingPortalUrl())",
                    feature: .rsa
                )
            }
        }

        return try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    let encrypted = try RSACryptographyHelper.encrypt(self, publicKey: publicKey)
                    continuation.resume(returning: encrypted)
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    /// Decrypts RSA or hybrid encrypted data
    /// - Parameter privateKey: RSA private key as Data
    /// - Returns: Decrypted data
    func decryptWithRSA(privateKey: Data) async throws -> Data {
        return try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    var decrypted = try RSACryptographyHelper.decrypt(self, privateKey: privateKey)

                    // Add watermark for unlicensed
                    if !isDebugMode && !ApiLicense.isRSAAvailable {
                        FeatureGate.applyRateLimitIfNeeded()
                        let prefix = Data(WatermarkHelper.unlicensedRSAPrefix.utf8)
                        let suffix = Data(WatermarkHelper.unlicensedRSASuffix.utf8)
                        var watermarked = Data()
                        watermarked.append(prefix)
                        watermarked.append(decrypted)
                        watermarked.append(suffix)
                        decrypted = watermarked
                    }

                    continuation.resume(returning: decrypted)
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    /// Signs data using RSA-PSS with SHA256
    /// - Parameter privateKey: RSA private key as Data
    /// - Returns: Signature
    func signWithRSA(privateKey: Data) async throws -> Data {
        // Check license for size limits
        if !isDebugMode && !ApiLicense.isRSAAvailable {
            FeatureGate.applyRateLimitIfNeeded()

            if self.count > FeatureGate.unlicensedRSAMaxLength {
                throw LicenseException(
                    "Unlicensed RSA signing is limited to \(FeatureGate.unlicensedRSAMaxLength) bytes.",
                    feature: .rsa
                )
            }
        }

        return try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    let signature = try RSACryptographyHelper.sign(self, privateKey: privateKey)
                    continuation.resume(returning: signature)
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    /// Verifies RSA-PSS signature
    /// - Parameters:
    ///   - signature: Signature to verify
    ///   - publicKey: RSA public key as Data
    /// - Returns: True if signature is valid
    func verifyRSASignature(signature: Data, publicKey: Data) async throws -> Bool {
        return try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    let result = try RSACryptographyHelper.verifySignature(self, signature: signature, publicKey: publicKey)
                    continuation.resume(returning: result)
                } catch {
                    continuation.resume(returning: false)
                }
            }
        }
    }

    /// Extracts public key from this private key data
    func getPublicKeyFromPrivateKey() async throws -> Data {
        return try RSACryptographyHelper.getPublicKey(from: self)
    }
}
