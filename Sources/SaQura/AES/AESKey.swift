// AESKey.swift
// SaQura Swift Library
// Copyright (c) 2025-2026 KyotoTech LLC. All rights reserved.

import Foundation
import CryptoKit

/// Generates and manages AES-256 encryption keys
public struct AESKey {
    /// AES key size in bytes (256 bits)
    public static let keySize = 32

    /// Generates a new cryptographically secure AES-256 key
    /// - Returns: Base64-encoded 256-bit key
    public static func newKey() -> String {
        let key = SymmetricKey(size: .bits256)
        return key.withUnsafeBytes { Data($0).toBase64() }
    }

    /// Generates a new AES-256 key asynchronously
    /// - Returns: Base64-encoded 256-bit key
    public static func newKeyAsync() async -> String {
        return await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                continuation.resume(returning: newKey())
            }
        }
    }

    /// Validates if the provided key is a valid AES-256 key
    /// - Parameter key: Base64-encoded key string
    /// - Returns: true if key is valid
    public static func isValid(_ key: String) -> Bool {
        guard let keyData = Data(base64Encoded: key) else { return false }
        return keyData.count == keySize || keyData.count == keySize * 2 // Also allow 64-byte keys for CBC+HMAC
    }

    /// Derives an AES key from a password
    /// - Parameters:
    ///   - password: The password to derive from
    ///   - salt: Salt for key derivation (should be random and stored)
    ///   - iterations: PBKDF2 iterations (default: 210000 for OWASP 2025)
    /// - Returns: Base64-encoded derived key
    public static func deriveFromPassword(
        _ password: String,
        salt: String,
        iterations: Int = 210_000
    ) -> String? {
        guard let saltData = salt.data(using: .utf8) else { return nil }
        guard let derivedKey = CryptoUtils.deriveKey(
            password: password,
            salt: saltData,
            iterations: iterations,
            keyLength: keySize
        ) else { return nil }
        return derivedKey.toBase64()
    }
}
