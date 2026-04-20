// AESExtensions.swift
// SaQura Swift Library
// Copyright (c) 2025-2026 KyotoTech LLC. All rights reserved.

import Foundation

// MARK: - String Extensions for AES

public extension String {
    /// Encrypts string using AES-256-GCM (authenticated encryption)
    /// - Parameter key: Base64-encoded 256-bit key
    /// - Returns: Base64-encoded encrypted data with nonce and tag
    /// - Throws: SaQuraError if encryption fails or license check fails
    func encryptWithAES(key: String) async throws -> String {
        // Check license for size limits (skip in debug)
        if !isDebugMode && !ApiLicense.isAESAvailable {
            FeatureGate.applyRateLimitIfNeeded()

            let dataSize = self.utf8.count
            if dataSize > FeatureGate.unlicensedAESMaxSize {
                throw SaQuraError.sizeLimitExceeded(
                    limit: FeatureGate.unlicensedAESMaxSize,
                    actual: dataSize,
                    feature: "AES"
                )
            }

            InternalLogger.warning("AES encryption used without license - output will be watermarked")
        }

        return try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    var encrypted = try AESCryptographyHelper.encrypt(self, key: key)

                    // Apply watermark for unlicensed
                    if !isDebugMode && !ApiLicense.isAESAvailable {
                        encrypted = WatermarkHelper.applyWatermarkToBase64(encrypted, context: "AES-GCM")
                    }

                    continuation.resume(returning: encrypted)
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    /// Decrypts string using AES-256-GCM with authentication
    /// - Parameter key: Base64-encoded 256-bit key
    /// - Returns: Decrypted plaintext
    /// - Throws: SaQuraError if decryption or authentication fails
    func decryptWithAES(key: String) async throws -> String {
        return try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    var cipherText = self

                    // Remove watermark if present
                    if WatermarkHelper.hasWatermark(cipherText) {
                        cipherText = WatermarkHelper.removeWatermarkFromBase64(cipherText)
                    }

                    var decrypted = try AESCryptographyHelper.decrypt(cipherText, key: key)

                    // Apply output watermark for unlicensed
                    if !isDebugMode && !ApiLicense.isAESAvailable {
                        FeatureGate.applyRateLimitIfNeeded()
                        decrypted = WatermarkHelper.unlicensedAESPrefix + " " + decrypted + " " + WatermarkHelper.unlicensedAESSuffix
                        InternalLogger.warning("AES decryption performed without license - output is watermarked")
                    }

                    continuation.resume(returning: decrypted)
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    /// Encrypts with password-based key derivation
    /// - Parameters:
    ///   - password: Password for key derivation
    ///   - salt: Salt for key derivation
    ///   - iterations: PBKDF2 iterations (default: 210000)
    /// - Returns: Encrypted text
    func encryptWithPassword(
        password: String,
        salt: String,
        iterations: Int = 210_000
    ) async throws -> String {
        guard let key = AESKey.deriveFromPassword(password, salt: salt, iterations: iterations) else {
            throw SaQuraError.keyGenerationFailed("Failed to derive key from password")
        }
        return try await encryptWithAES(key: key)
    }

    /// Decrypts with password-based key derivation
    /// - Parameters:
    ///   - password: Password for key derivation
    ///   - salt: Salt for key derivation
    ///   - iterations: PBKDF2 iterations (default: 210000)
    /// - Returns: Decrypted text
    func decryptWithPassword(
        password: String,
        salt: String,
        iterations: Int = 210_000
    ) async throws -> String {
        guard let key = AESKey.deriveFromPassword(password, salt: salt, iterations: iterations) else {
            throw SaQuraError.keyGenerationFailed("Failed to derive key from password")
        }
        return try await decryptWithAES(key: key)
    }
}

// MARK: - Data Extensions for AES

public extension Data {
    /// Encrypts data using AES-256-GCM
    /// - Parameter key: Base64-encoded 256-bit key
    /// - Returns: Encrypted data with nonce and tag
    func encryptWithAES(key: String) async throws -> Data {
        // Check license for size limits
        if !isDebugMode && !ApiLicense.isAESAvailable {
            FeatureGate.applyRateLimitIfNeeded()

            if self.count > FeatureGate.unlicensedAESMaxSize {
                throw SaQuraError.sizeLimitExceeded(
                    limit: FeatureGate.unlicensedAESMaxSize,
                    actual: self.count,
                    feature: "AES"
                )
            }
        }

        return try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    let encrypted = try AESCryptographyHelper.encrypt(self, key: key)

                    // Apply watermark for unlicensed
                    if !isDebugMode && !ApiLicense.isAESAvailable {
                        let watermarked = WatermarkHelper.applyWatermark(encrypted, context: "AES-GCM-Binary")
                        continuation.resume(returning: watermarked)
                    } else {
                        continuation.resume(returning: encrypted)
                    }
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    /// Decrypts data using AES-256-GCM
    /// - Parameter key: Base64-encoded 256-bit key
    /// - Returns: Decrypted data
    func decryptWithAES(key: String) async throws -> Data {
        return try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    var dataToDecrypt = self

                    // Remove watermark if present
                    if WatermarkHelper.hasWatermark(self) {
                        dataToDecrypt = WatermarkHelper.removeWatermark(self)
                    }

                    let decrypted = try AESCryptographyHelper.decrypt(dataToDecrypt, key: key)

                    // Note: We don't watermark binary output for decryption
                    // as it would corrupt the data

                    continuation.resume(returning: decrypted)
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }
}
