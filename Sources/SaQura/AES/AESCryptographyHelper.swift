// AESCryptographyHelper.swift
// SaQura Swift Library
// Copyright (c) 2025-2026 KyotoTech LLC. All rights reserved.

import Foundation
import CryptoKit
import CommonCrypto

/// Internal helper for AES encryption with GCM and CBC+HMAC modes
/// Format: [Nonce:12][Ciphertext][Tag:16] - compatible with .NET SaQura
internal struct AESCryptographyHelper {
    // AES-GCM constants (matches .NET)
    private static let gcmNonceSize = 12  // 96 bits
    private static let gcmTagSize = 16    // 128 bits

    // AES-CBC constants (legacy support)
    private static let cbcIVSize = 16     // 128 bits
    private static let hmacSize = 32      // 256 bits for HMAC-SHA256

    // Key sizes
    private static let aesKeySize = 32    // 256 bits

    // MARK: - GCM Encryption (Primary)

    /// Encrypts using AES-GCM with automatic nonce generation
    /// - Parameters:
    ///   - plainText: Text to encrypt
    ///   - key: Base64-encoded 256-bit key
    /// - Returns: Base64-encoded encrypted data (nonce || ciphertext || tag)
    static func encrypt(_ plainText: String, key: String) throws -> String {
        guard !plainText.isEmpty else {
            throw SaQuraError.invalidInput("Plain text cannot be empty")
        }
        guard !key.isEmpty else {
            throw SaQuraError.invalidKey("Encryption key cannot be empty")
        }

        let plainData = Data(plainText.utf8)
        let keyData = try convertKey(key)

        let encryptedData = try encryptGCM(plainData, key: keyData)
        return encryptedData.toBase64()
    }

    /// Encrypts byte data using AES-GCM
    static func encrypt(_ data: Data, key: String) throws -> Data {
        guard !data.isEmpty else {
            throw SaQuraError.invalidInput("Data cannot be empty")
        }
        let keyData = try convertKey(key)
        return try encryptGCM(data, key: keyData)
    }

    /// Core GCM encryption
    private static func encryptGCM(_ plainText: Data, key: Data) throws -> Data {
        let symmetricKey = SymmetricKey(data: key)
        let nonce = AES.GCM.Nonce()

        do {
            let sealedBox = try AES.GCM.seal(plainText, using: symmetricKey, nonce: nonce)

            // Format: [Nonce:12][Ciphertext:N][Tag:16] - same as .NET
            var result = Data()
            result.append(contentsOf: nonce)
            result.append(sealedBox.ciphertext)
            result.append(sealedBox.tag)

            return result
        } catch {
            throw SaQuraError.encryptionFailed("AES-GCM encryption failed: \(error.localizedDescription)")
        }
    }

    // MARK: - GCM Decryption

    /// Decrypts using AES-GCM with authentication
    /// - Parameters:
    ///   - cipherText: Base64-encoded encrypted data
    ///   - key: Base64-encoded 256-bit key
    /// - Returns: Decrypted plain text
    static func decrypt(_ cipherText: String, key: String) throws -> String {
        guard !cipherText.trimmingCharacters(in: .whitespaces).isEmpty else {
            throw SaQuraError.invalidInput("Cipher text cannot be empty")
        }
        guard !key.isEmpty else {
            throw SaQuraError.invalidKey("Encryption key cannot be empty")
        }

        guard let encryptedData = Data(base64Encoded: cipherText) else {
            throw SaQuraError.invalidInput("Invalid Base64 cipher text")
        }

        let keyData = try convertKey(key)
        let decryptedData = try decryptAuto(encryptedData, key: keyData)

        guard let plainText = String(data: decryptedData, encoding: .utf8) else {
            throw SaQuraError.decryptionFailed("Failed to decode decrypted data as UTF-8")
        }

        return plainText
    }

    /// Decrypts byte data
    static func decrypt(_ data: Data, key: String) throws -> Data {
        let keyData = try convertKey(key)
        return try decryptAuto(data, key: keyData)
    }

    /// Auto-detects format and decrypts (GCM or CBC+HMAC)
    private static func decryptAuto(_ encryptedData: Data, key: Data) throws -> Data {
        // Minimum size check for GCM
        let minGCMSize = gcmNonceSize + gcmTagSize + 1

        // Try GCM first (new format)
        if encryptedData.count >= minGCMSize {
            do {
                return try decryptGCM(encryptedData, key: key)
            } catch {
                // Fall through to try CBC+HMAC
                InternalLogger.debug("GCM decryption failed, trying CBC+HMAC")
            }
        }

        // Try CBC+HMAC (legacy format)
        let minCBCSize = cbcIVSize + hmacSize + 1
        if encryptedData.count >= minCBCSize {
            return try decryptCBCHMAC(encryptedData, key: key)
        }

        throw SaQuraError.decryptionFailed("Invalid encrypted data format")
    }

    /// Core GCM decryption
    private static func decryptGCM(_ encryptedData: Data, key: Data) throws -> Data {
        guard encryptedData.count >= gcmNonceSize + gcmTagSize else {
            throw SaQuraError.decryptionFailed("Invalid GCM encrypted data")
        }

        // Extract components: [Nonce:12][Ciphertext:N][Tag:16]
        let nonce = encryptedData.prefix(gcmNonceSize)
        let tagStart = encryptedData.count - gcmTagSize
        let ciphertext = encryptedData[gcmNonceSize..<tagStart]
        let tag = encryptedData.suffix(gcmTagSize)

        let symmetricKey = SymmetricKey(data: key)

        do {
            let gcmNonce = try AES.GCM.Nonce(data: nonce)
            let sealedBox = try AES.GCM.SealedBox(
                nonce: gcmNonce,
                ciphertext: ciphertext,
                tag: tag
            )
            return try AES.GCM.open(sealedBox, using: symmetricKey)
        } catch {
            throw SaQuraError.decryptionFailed("AES-GCM decryption failed: \(error.localizedDescription)")
        }
    }

    // MARK: - CBC+HMAC (Legacy Support)

    /// Decrypts using AES-CBC with HMAC verification (for .NET compatibility)
    private static func decryptCBCHMAC(_ encryptedData: Data, key: Data) throws -> Data {
        guard encryptedData.count >= cbcIVSize + hmacSize + 1 else {
            throw SaQuraError.decryptionFailed("Invalid CBC-HMAC encrypted data")
        }

        // Derive encryption and MAC keys
        let (encKey, macKey) = deriveKeysForCBC(from: key)

        // Extract components: [IV:16][Ciphertext:N][MAC:32]
        let iv = encryptedData.prefix(cbcIVSize)
        let macStart = encryptedData.count - hmacSize
        let ciphertext = encryptedData[cbcIVSize..<macStart]
        let mac = encryptedData.suffix(hmacSize)

        // Verify MAC first (Encrypt-then-MAC)
        var toMac = Data()
        toMac.append(iv)
        toMac.append(ciphertext)
        let expectedMac = toMac.hmacSHA256(key: macKey)

        guard mac.secureCompare(expectedMac) else {
            throw SaQuraError.decryptionFailed("MAC verification failed")
        }

        // Decrypt after MAC verification
        return try decryptCBC(Data(ciphertext), key: encKey, iv: Data(iv))
    }

    /// Core CBC decryption using CommonCrypto
    private static func decryptCBC(_ ciphertext: Data, key: Data, iv: Data) throws -> Data {
        let bufferSize = ciphertext.count + kCCBlockSizeAES128
        var decryptedData = Data(count: bufferSize)
        var decryptedLength: Int = 0

        let status = decryptedData.withUnsafeMutableBytes { decryptedPtr in
            ciphertext.withUnsafeBytes { ciphertextPtr in
                key.withUnsafeBytes { keyPtr in
                    iv.withUnsafeBytes { ivPtr in
                        CCCrypt(
                            CCOperation(kCCDecrypt),
                            CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(kCCOptionPKCS7Padding),
                            keyPtr.baseAddress, key.count,
                            ivPtr.baseAddress,
                            ciphertextPtr.baseAddress, ciphertext.count,
                            decryptedPtr.baseAddress, bufferSize,
                            &decryptedLength
                        )
                    }
                }
            }
        }

        guard status == kCCSuccess else {
            throw SaQuraError.decryptionFailed("AES-CBC decryption failed with status: \(status)")
        }

        return decryptedData.prefix(decryptedLength)
    }

    // MARK: - Key Handling

    /// Converts key from Base64 or derives proper key size
    private static func convertKey(_ key: String) throws -> Data {
        // Try to parse as Base64
        if let keyData = Data(base64Encoded: key) {
            if keyData.count == aesKeySize || keyData.count == aesKeySize * 2 {
                return keyData.prefix(aesKeySize)
            }
            // Wrong size - derive key
            return keyData.sha256()
        }

        // Not valid Base64 - derive key from string
        return Data(key.utf8).sha256()
    }

    /// Derives encryption and MAC keys for CBC+HMAC mode
    private static func deriveKeysForCBC(from key: Data) -> (encKey: Data, macKey: Data) {
        if key.count == aesKeySize * 2 {
            // 64-byte key: first half for encryption, second for MAC
            return (key.prefix(aesKeySize), key.suffix(aesKeySize))
        } else if key.count == aesKeySize {
            // 32-byte key: derive MAC key
            let encKey = key
            let macKey = Data("MAC".utf8).hmacSHA256(key: key)
            return (encKey, macKey)
        } else {
            // Invalid size - derive both
            let derived = key.sha256()
            let macKey = Data("MAC".utf8).hmacSHA256(key: derived)
            return (derived, macKey)
        }
    }
}
