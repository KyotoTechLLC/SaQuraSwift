// QGeneration2.swift
// SaQura Swift Library
// Copyright (c) 2025-2026 KyotoTech LLC. All rights reserved.

import Foundation
import CryptoKit

/// Generation 2: Classic McEliece + AES-256-CBC + HMAC-SHA256
/// Compatible with .NET SaQura PqGeneration2
///
/// Key format: [0x02][Strength][RawKey...]
/// Encrypt: CMCE encaps → HKDF-SHA256(salt=empty, info=empty) → AES-256-CBC(PKCS7) → HMAC-SHA256
/// Wire: encapsulated = CMCE-Capsule, encrypted = [IV:16][CBC_Ciphertext][HMAC:32]
///
/// CRITICAL: HMAC key is the RAW shared secret, NOT the derived AES key
/// CRITICAL: HKDF with empty salt + empty info
internal struct QGeneration2 {
    private static let generationByte: UInt8 = 0x02

    // MARK: - Key Generation

    /// Generates a Gen2 key pair using Classic McEliece (strength-based)
    /// Header: [0x02][Strength][RawPublicKey...]
    static func generateKeyPair(strength: QuantumStrength) throws -> (publicKey: Data, privateKey: Data) {
        let kem = try CMCEHelper.createKem(for: strength)
        let (rawPublicKey, rawSecretKey) = try kem.generateKeyPair()

        // Format: [Gen:1][Strength:1][RawKey...]
        var publicKeyResult = Data()
        publicKeyResult.append(generationByte)
        publicKeyResult.append(strength.rawValue)
        publicKeyResult.append(rawPublicKey)

        var privateKeyResult = Data()
        privateKeyResult.append(generationByte)
        privateKeyResult.append(strength.rawValue)
        privateKeyResult.append(rawSecretKey)

        return (publicKeyResult, privateKeyResult)
    }

    // MARK: - Encryption

    /// Encrypts a message using Gen2: CMCE encapsulation + HKDF + AES-CBC + HMAC
    /// HKDF: SHA256, salt=empty, info=empty → 32 bytes for AES key
    /// HMAC: SHA256 with raw shared secret as key, computed over IV+ciphertext
    /// Wire: encapsulated = CMCE capsule, encrypted = [IV:16][CBC_Ciphertext][HMAC:32]
    static func encrypt(
        _ message: String,
        publicKey: Data
    ) throws -> (encapsulatedSecret: Data, encryptedMessage: Data) {
        guard publicKey.count >= 2 else {
            throw SaQuraError.invalidKey("Invalid Gen2 public key")
        }

        // Extract strength and raw public key
        let strength = QuantumStrength(rawValue: publicKey[1]) ?? .standard
        let rawPublicKey = Data(publicKey.suffix(from: 2))

        // Encapsulate using Classic McEliece
        let kem = try CMCEHelper.createKem(for: strength)
        let (capsule, sharedSecret) = try kem.encapsulate(publicKey: rawPublicKey)

        // HKDF-SHA256 with empty salt and empty info → AES key
        let aesKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: sharedSecret),
            salt: Data(),
            info: Data(),
            outputByteCount: 32
        )
        let aesKeyData = aesKey.withUnsafeBytes { Data($0) }

        // Generate random IV
        let iv = Data.secureRandom(count: 16)

        // AES-256-CBC encrypt with PKCS7 padding
        let messageData = Data(message.utf8)
        let cbcCiphertext = try AESCBCHelper.encrypt(plaintext: messageData, key: aesKeyData, iv: iv)

        // HMAC-SHA256 with RAW shared secret as key, over IV + ciphertext
        let hmacKey = SymmetricKey(data: sharedSecret)
        var hmacInput = Data()
        hmacInput.append(iv)
        hmacInput.append(cbcCiphertext)
        let hmac = HMAC<SHA256>.authenticationCode(for: hmacInput, using: hmacKey)

        // Encapsulated: raw CMCE capsule
        let encapsulatedSecret = capsule

        // Encrypted: [IV:16][CBC_Ciphertext][HMAC:32]
        var encryptedMessage = Data()
        encryptedMessage.append(iv)
        encryptedMessage.append(cbcCiphertext)
        encryptedMessage.append(Data(hmac))

        return (encapsulatedSecret, encryptedMessage)
    }

    // MARK: - Decryption

    /// Decrypts a message using Gen2 algorithm
    static func decrypt(
        _ encryptedMessage: Data,
        privateKey: Data,
        secret: Data?
    ) throws -> String {
        guard privateKey.count >= 2 else {
            throw SaQuraError.invalidKey("Invalid Gen2 private key")
        }

        guard let encapsulatedSecret = secret, !encapsulatedSecret.isEmpty else {
            throw SaQuraError.invalidInput("Encapsulated secret required for Gen2 decryption")
        }

        // Minimum: IV(16) + at least 1 block(16) + HMAC(32) = 64
        guard encryptedMessage.count >= 64 else {
            throw SaQuraError.invalidInput("Invalid Gen2 encrypted message")
        }

        // Extract strength and raw secret key
        let strength = QuantumStrength(rawValue: privateKey[1]) ?? .standard
        let rawSecretKey = Data(privateKey.suffix(from: 2))

        // Decapsulate using Classic McEliece
        let kem = try CMCEHelper.createKem(for: strength)
        let sharedSecret = try kem.decapsulate(ciphertext: encapsulatedSecret, secretKey: rawSecretKey)

        // Parse encrypted message: [IV:16][CBC_Ciphertext:N][HMAC:32]
        let iv = Data(encryptedMessage.prefix(16))
        let hmacStored = Data(encryptedMessage.suffix(32))
        let cbcCiphertext = Data(encryptedMessage[16..<(encryptedMessage.count - 32)])

        // Verify HMAC-SHA256 with RAW shared secret
        let hmacKey = SymmetricKey(data: sharedSecret)
        var hmacInput = Data()
        hmacInput.append(iv)
        hmacInput.append(cbcCiphertext)
        let hmacComputed = HMAC<SHA256>.authenticationCode(for: hmacInput, using: hmacKey)
        guard Data(hmacComputed).secureCompare(hmacStored) else {
            throw SaQuraError.decryptionFailed("HMAC verification failed")
        }

        // HKDF-SHA256 with empty salt and empty info → AES key
        let aesKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: sharedSecret),
            salt: Data(),
            info: Data(),
            outputByteCount: 32
        )
        let aesKeyData = aesKey.withUnsafeBytes { Data($0) }

        // AES-256-CBC decrypt
        let decryptedData = try AESCBCHelper.decrypt(ciphertext: cbcCiphertext, key: aesKeyData, iv: iv)

        guard let plaintext = String(data: decryptedData, encoding: .utf8) else {
            throw SaQuraError.decryptionFailed("Failed to decode as UTF-8")
        }

        return plaintext
    }
}
