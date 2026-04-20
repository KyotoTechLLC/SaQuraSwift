// RSACryptographyHelper.swift
// SaQura Swift Library
// Copyright (c) 2025-2026 KyotoTech LLC. All rights reserved.

import Foundation
import Security
import CryptoKit

/// Internal helper for RSA encryption with OAEP-SHA256 and hybrid encryption
/// Compatible with .NET SaQura RSA implementation
internal struct RSACryptographyHelper {
    // RSA-4096 with OAEP-SHA256 can encrypt max 446 bytes
    private static let maxRSAPlaintextSize = 446

    // Hybrid encryption header (matches .NET)
    private static let hybridHeader = Data([0x48, 0x59, 0x42, 0x52]) // "HYBR"

    // MARK: - Encryption

    /// Encrypts string with RSA or hybrid encryption
    static func encrypt(_ plainText: String, publicKey: String) throws -> String {
        let data = Data(plainText.utf8)
        let encrypted = try encrypt(data, publicKeyPEM: publicKey)
        return encrypted.toBase64()
    }

    /// Encrypts data with RSA or hybrid encryption
    static func encrypt(_ data: Data, publicKeyPEM: String) throws -> Data {
        guard let secKey = RSAKey.importPublicKey(from: publicKeyPEM) else {
            throw SaQuraError.invalidKey("Invalid public key")
        }

        if data.count <= maxRSAPlaintextSize {
            // Direct RSA encryption
            return try encryptRSA(data, publicKey: secKey)
        } else {
            // Hybrid encryption for large data
            return try encryptHybrid(data, publicKey: secKey)
        }
    }

    /// Encrypts data with RSA or hybrid encryption (byte array key)
    static func encrypt(_ data: Data, publicKey: Data) throws -> Data {
        let pem = try dataToPEM(publicKey, isPublic: true)
        return try encrypt(data, publicKeyPEM: pem)
    }

    /// Direct RSA encryption with OAEP-SHA256
    private static func encryptRSA(_ data: Data, publicKey: SecKey) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let encrypted = SecKeyCreateEncryptedData(
            publicKey,
            .rsaEncryptionOAEPSHA256,
            data as CFData,
            &error
        ) else {
            throw SaQuraError.encryptionFailed(error?.takeRetainedValue().localizedDescription ?? "RSA encryption failed")
        }
        return encrypted as Data
    }

    /// Hybrid encryption: RSA-encrypted AES key + AES-GCM encrypted data
    private static func encryptHybrid(_ data: Data, publicKey: SecKey) throws -> Data {
        // Generate random AES key
        let aesKey = Data.secureRandom(count: 32)

        // Encrypt data with AES-GCM
        let encryptedData = try AESCryptographyHelper.encrypt(data, key: aesKey.toBase64())

        // Encrypt AES key with RSA
        let encryptedKey = try encryptRSA(aesKey, publicKey: publicKey)

        // Format: [HYBR:4][KeyLength:4][EncryptedKey][EncryptedData]
        var result = Data()
        result.append(hybridHeader)

        var keyLength = UInt32(encryptedKey.count).bigEndian
        result.append(Data(bytes: &keyLength, count: 4))
        result.append(encryptedKey)
        result.append(encryptedData)

        return result
    }

    // MARK: - Decryption

    /// Decrypts string with RSA or hybrid decryption
    static func decrypt(_ cipherText: String, privateKey: String) throws -> String {
        guard let data = Data(base64Encoded: cipherText) else {
            throw SaQuraError.invalidInput("Invalid Base64 cipher text")
        }

        let decrypted = try decrypt(data, privateKeyPEM: privateKey)

        guard let plainText = String(data: decrypted, encoding: .utf8) else {
            throw SaQuraError.decryptionFailed("Failed to decode decrypted data as UTF-8")
        }

        return plainText
    }

    /// Decrypts data with RSA or hybrid decryption
    static func decrypt(_ data: Data, privateKeyPEM: String) throws -> Data {
        guard let secKey = RSAKey.importPrivateKey(from: privateKeyPEM) else {
            throw SaQuraError.invalidKey("Invalid private key")
        }

        // Check for hybrid encryption
        if data.count >= 8 && data.prefix(4) == hybridHeader {
            return try decryptHybrid(data, privateKey: secKey)
        } else {
            return try decryptRSA(data, privateKey: secKey)
        }
    }

    /// Decrypts data with RSA or hybrid decryption (byte array key)
    static func decrypt(_ data: Data, privateKey: Data) throws -> Data {
        let pem = try dataToPEM(privateKey, isPublic: false)
        return try decrypt(data, privateKeyPEM: pem)
    }

    /// Direct RSA decryption with OAEP-SHA256
    private static func decryptRSA(_ data: Data, privateKey: SecKey) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let decrypted = SecKeyCreateDecryptedData(
            privateKey,
            .rsaEncryptionOAEPSHA256,
            data as CFData,
            &error
        ) else {
            throw SaQuraError.decryptionFailed(error?.takeRetainedValue().localizedDescription ?? "RSA decryption failed")
        }
        return decrypted as Data
    }

    /// Hybrid decryption: RSA-decrypted AES key + AES-GCM decrypted data
    private static func decryptHybrid(_ data: Data, privateKey: SecKey) throws -> Data {
        // Extract key length
        let keyLengthBytes = data[4..<8]
        let keyLength = keyLengthBytes.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self).bigEndian }

        // Extract encrypted key
        let keyStart = 8
        let keyEnd = keyStart + Int(keyLength)
        guard keyEnd < data.count else {
            throw SaQuraError.decryptionFailed("Invalid hybrid encrypted data")
        }

        let encryptedKey = data[keyStart..<keyEnd]
        let encryptedData = data[keyEnd...]

        // Decrypt AES key with RSA
        let aesKey = try decryptRSA(Data(encryptedKey), privateKey: privateKey)

        // Decrypt data with AES-GCM
        return try AESCryptographyHelper.decrypt(Data(encryptedData), key: aesKey.toBase64())
    }

    // MARK: - Signatures

    /// Signs data using RSA-PSS with SHA256
    static func sign(_ data: Data, privateKey: Data) throws -> Data {
        let pem = try dataToPEM(privateKey, isPublic: false)
        return try sign(data, privateKeyPEM: pem)
    }

    /// Signs data using RSA-PSS with SHA256
    static func sign(_ data: Data, privateKeyPEM: String) throws -> Data {
        guard let secKey = RSAKey.importPrivateKey(from: privateKeyPEM) else {
            throw SaQuraError.invalidKey("Invalid private key")
        }

        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            secKey,
            .rsaSignatureMessagePSSSHA256,
            data as CFData,
            &error
        ) else {
            throw SaQuraError.signatureInvalid(error?.takeRetainedValue().localizedDescription ?? "Signing failed")
        }

        return signature as Data
    }

    /// Verifies RSA-PSS signature
    static func verifySignature(_ data: Data, signature: Data, publicKey: Data) throws -> Bool {
        let pem = try dataToPEM(publicKey, isPublic: true)
        return try verifySignature(data, signature: signature, publicKeyPEM: pem)
    }

    /// Verifies RSA-PSS signature
    static func verifySignature(_ data: Data, signature: Data, publicKeyPEM: String) throws -> Bool {
        guard let secKey = RSAKey.importPublicKey(from: publicKeyPEM) else {
            throw SaQuraError.invalidKey("Invalid public key")
        }

        var error: Unmanaged<CFError>?
        let result = SecKeyVerifySignature(
            secKey,
            .rsaSignatureMessagePSSSHA256,
            data as CFData,
            signature as CFData,
            &error
        )

        return result
    }

    // MARK: - Key Utilities

    /// Extracts public key from private key
    static func getPublicKey(from privateKeyData: Data) throws -> Data {
        let pem = try dataToPEM(privateKeyData, isPublic: false)
        guard let privateKey = RSAKey.importPrivateKey(from: pem) else {
            throw SaQuraError.invalidKey("Invalid private key")
        }

        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw SaQuraError.invalidKey("Failed to extract public key")
        }

        var error: Unmanaged<CFError>?
        guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            throw SaQuraError.invalidKey("Failed to export public key")
        }

        return publicKeyData
    }

    /// Validates private key format
    static func isValidPrivateKey(_ pem: String) -> Bool {
        return RSAKey.importPrivateKey(from: pem) != nil
    }

    /// Validates public key format
    static func isValidPublicKey(_ pem: String) -> Bool {
        return RSAKey.importPublicKey(from: pem) != nil
    }

    // MARK: - PEM Conversion

    /// Converts raw key data to PEM format
    private static func dataToPEM(_ data: Data, isPublic: Bool) throws -> String {
        let base64 = data.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])

        if isPublic {
            return """
            -----BEGIN PUBLIC KEY-----
            \(base64)
            -----END PUBLIC KEY-----
            """
        } else {
            return """
            -----BEGIN PRIVATE KEY-----
            \(base64)
            -----END PRIVATE KEY-----
            """
        }
    }
}
