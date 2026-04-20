// QGeneration5.swift
// SaQura Swift Library
// Copyright (c) 2025-2026 KyotoTech LLC. All rights reserved.

import Foundation
import CryptoKit

/// Generation 5: Classic McEliece + AES-256-CBC + HMAC-SHA256 (with salt)
/// Compatible with .NET SaQura QGeneration5
///
/// Key format: [0x05][Strength][RawKey...]
/// Encrypt: CMCE encaps → HKDF-SHA256(salt=random32, info="Gen5-CMCE-HMAC", output=64)
///          → Split: AES-Key(32) + MAC-Key(32)
///          → AES-256-CBC(PKCS7) → HMAC-SHA256(key=MAC-Key, data=salt+IV+ciphertext)
/// Wire: encapsulated = CMCE-Capsule, encrypted = [Salt:32][IV:16][CBC_Ciphertext][HMAC:32]
internal struct QGeneration5 {
    private static let generationByte: UInt8 = 0x05
    private static let hkdfInfo = Data("Gen5-CMCE-HMAC".utf8)

    // MARK: - Key Generation

    /// Generates a Gen5 key pair using Classic McEliece (strength-based)
    /// Header: [0x05][Strength][RawPublicKey...]
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

    /// Encrypts a message using Gen5: CMCE encapsulation + HKDF + AES-CBC + HMAC
    /// HKDF: SHA256, salt=random32, info="Gen5-CMCE-HMAC", output=64 bytes
    ///       → first 32 bytes = AES key, last 32 bytes = MAC key
    /// Wire: encapsulated = CMCE capsule, encrypted = [Salt:32][IV:16][CBC_Ciphertext][HMAC:32]
    static func encrypt(
        _ message: String,
        publicKey: Data
    ) throws -> (encapsulatedSecret: Data, encryptedMessage: Data) {
        guard publicKey.count >= 2 else {
            throw SaQuraError.invalidKey("Invalid Gen5 public key")
        }

        // Extract strength and raw public key
        let strength = QuantumStrength(rawValue: publicKey[1]) ?? .standard
        let rawPublicKey = Data(publicKey.suffix(from: 2))

        // Encapsulate using Classic McEliece
        let kem = try CMCEHelper.createKem(for: strength)
        let (capsule, sharedSecret) = try kem.encapsulate(publicKey: rawPublicKey)

        // HKDF-SHA256: salt=random32, info="Gen5-CMCE-HMAC", output=64 bytes
        let salt = Data.secureRandom(count: 32)
        let derivedKeyMaterial = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: sharedSecret),
            salt: salt,
            info: hkdfInfo,
            outputByteCount: 64
        )

        // Split derived key: first 32 = AES key, last 32 = MAC key
        let derivedBytes = derivedKeyMaterial.withUnsafeBytes { Data($0) }
        let aesKeyData = Data(derivedBytes.prefix(32))
        let macKeyData = Data(derivedBytes.suffix(32))

        // Generate random IV
        let iv = Data.secureRandom(count: 16)

        // AES-256-CBC encrypt with PKCS7 padding
        let messageData = Data(message.utf8)
        let cbcCiphertext = try AESCBCHelper.encrypt(plaintext: messageData, key: aesKeyData, iv: iv)

        // HMAC-SHA256 with MAC key over salt + IV + ciphertext
        let macKey = SymmetricKey(data: macKeyData)
        var hmacInput = Data()
        hmacInput.append(salt)
        hmacInput.append(iv)
        hmacInput.append(cbcCiphertext)
        let hmac = HMAC<SHA256>.authenticationCode(for: hmacInput, using: macKey)

        // Encapsulated: raw CMCE capsule
        let encapsulatedSecret = capsule

        // Encrypted: [Salt:32][IV:16][CBC_Ciphertext][HMAC:32]
        var encryptedMessage = Data()
        encryptedMessage.append(salt)
        encryptedMessage.append(iv)
        encryptedMessage.append(cbcCiphertext)
        encryptedMessage.append(Data(hmac))

        return (encapsulatedSecret, encryptedMessage)
    }

    // MARK: - Decryption

    /// Decrypts a message using Gen5 algorithm
    static func decrypt(
        _ encryptedMessage: Data,
        privateKey: Data,
        secret: Data?
    ) throws -> String {
        guard privateKey.count >= 2 else {
            throw SaQuraError.invalidKey("Invalid Gen5 private key")
        }

        guard let encapsulatedSecret = secret, !encapsulatedSecret.isEmpty else {
            throw SaQuraError.invalidInput("Encapsulated secret required for Gen5 decryption")
        }

        // Minimum: Salt(32) + IV(16) + at least 1 block(16) + HMAC(32) = 96
        guard encryptedMessage.count >= 96 else {
            throw SaQuraError.invalidInput("Invalid Gen5 encrypted message")
        }

        // Extract strength and raw secret key
        let strength = QuantumStrength(rawValue: privateKey[1]) ?? .standard
        let rawSecretKey = Data(privateKey.suffix(from: 2))

        // Decapsulate using Classic McEliece
        let kem = try CMCEHelper.createKem(for: strength)
        let sharedSecret = try kem.decapsulate(ciphertext: encapsulatedSecret, secretKey: rawSecretKey)

        // Parse encrypted message: [Salt:32][IV:16][CBC_Ciphertext:N][HMAC:32]
        let salt = Data(encryptedMessage.prefix(32))
        let iv = Data(encryptedMessage[32..<48])
        let hmacStored = Data(encryptedMessage.suffix(32))
        let cbcCiphertext = Data(encryptedMessage[48..<(encryptedMessage.count - 32)])

        // HKDF-SHA256: same params as encrypt
        let derivedKeyMaterial = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: sharedSecret),
            salt: salt,
            info: hkdfInfo,
            outputByteCount: 64
        )

        // Split derived key
        let derivedBytes = derivedKeyMaterial.withUnsafeBytes { Data($0) }
        let aesKeyData = Data(derivedBytes.prefix(32))
        let macKeyData = Data(derivedBytes.suffix(32))

        // Verify HMAC-SHA256 with MAC key over salt + IV + ciphertext
        let macKey = SymmetricKey(data: macKeyData)
        var hmacInput = Data()
        hmacInput.append(salt)
        hmacInput.append(iv)
        hmacInput.append(cbcCiphertext)
        let hmacComputed = HMAC<SHA256>.authenticationCode(for: hmacInput, using: macKey)
        guard Data(hmacComputed).secureCompare(hmacStored) else {
            throw SaQuraError.decryptionFailed("HMAC verification failed")
        }

        // AES-256-CBC decrypt
        let decryptedData = try AESCBCHelper.decrypt(ciphertext: cbcCiphertext, key: aesKeyData, iv: iv)

        guard let plaintext = String(data: decryptedData, encoding: .utf8) else {
            throw SaQuraError.decryptionFailed("Failed to decode as UTF-8")
        }

        return plaintext
    }
}
