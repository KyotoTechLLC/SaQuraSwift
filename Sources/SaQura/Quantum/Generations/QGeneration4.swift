// QGeneration4.swift
// SaQura Swift Library
// Copyright (c) 2025-2026 KyotoTech LLC. All rights reserved.

import Foundation
import CryptoKit

/// Generation 4: FrodoKEM-1344-AES + AES-256-GCM
/// Always uses FrodoKEM-1344-AES (fixed, independent of strength parameter)
/// Compatible with .NET SaQura PqGeneration4
internal struct QGeneration4 {
    private static let generationByte: UInt8 = 0x04
    private static let strengthByte: UInt8 = QuantumStrength.highest.rawValue // Always Highest (0x02)

    // MARK: - Key Generation

    /// Generates a Gen4 key pair using FrodoKEM-1344-AES
    /// Header: [0x04][0x02][RawPublicKey...]
    static func generateKeyPair(strength: QuantumStrength) throws -> (publicKey: Data, privateKey: Data) {
        let kem = try OQSKem(algorithm: .frodokem1344aes)
        let (rawPublicKey, rawSecretKey) = try kem.generateKeyPair()

        // Format: [Gen:1][Strength:1][RawKey...]
        var publicKeyResult = Data()
        publicKeyResult.append(generationByte)
        publicKeyResult.append(strengthByte)
        publicKeyResult.append(rawPublicKey)

        var privateKeyResult = Data()
        privateKeyResult.append(generationByte)
        privateKeyResult.append(strengthByte)
        privateKeyResult.append(rawSecretKey)

        return (publicKeyResult, privateKeyResult)
    }

    // MARK: - Encryption

    /// Encrypts a message using Gen4: FrodoKEM-1344 encapsulation + custom KDF + AES-GCM
    /// Custom KDF: HMAC-SHA256(key=sharedSecret, data=[0x01]).prefix(32)
    /// Wire format encapsulated: raw Frodo ciphertext
    /// Wire format encrypted: [Nonce:12][Ciphertext][Tag:16]
    static func encrypt(
        _ message: String,
        publicKey: Data
    ) throws -> (encapsulatedSecret: Data, encryptedMessage: Data) {
        guard publicKey.count >= 2 else {
            throw SaQuraError.invalidKey("Invalid Gen4 public key")
        }

        // Extract raw public key (skip 2-byte header)
        let rawPublicKey = Data(publicKey.suffix(from: 2))

        // Encapsulate using FrodoKEM-1344-AES
        let kem = try OQSKem(algorithm: .frodokem1344aes)
        let (ciphertext, sharedSecret) = try kem.encapsulate(publicKey: rawPublicKey)

        // Custom KDF: HMAC-SHA256(key=sharedSecret, data=[0x01]).prefix(32)
        // This is NOT standard HKDF — it's the .NET PqGeneration4 custom KDF
        let hmacKey = SymmetricKey(data: sharedSecret)
        let kdfInput = Data([0x01])
        let derivedKeyData = Data(HMAC<SHA256>.authenticationCode(for: kdfInput, using: hmacKey))
        let symmetricKey = SymmetricKey(data: derivedKeyData.prefix(32))

        // Encrypt with AES-GCM
        let messageData = Data(message.utf8)
        let nonce = AES.GCM.Nonce()

        guard let sealedBox = try? AES.GCM.seal(messageData, using: symmetricKey, nonce: nonce) else {
            throw SaQuraError.encryptionFailed("AES-GCM encryption failed")
        }

        // Encapsulated: raw Frodo ciphertext
        let encapsulatedSecret = ciphertext

        // Encrypted: [Nonce:12][Ciphertext][Tag:16]
        var encryptedMessage = Data()
        encryptedMessage.append(contentsOf: nonce)
        encryptedMessage.append(sealedBox.ciphertext)
        encryptedMessage.append(sealedBox.tag)

        return (encapsulatedSecret, encryptedMessage)
    }

    // MARK: - Decryption

    /// Decrypts a message using Gen4 algorithm
    static func decrypt(
        _ encryptedMessage: Data,
        privateKey: Data,
        secret: Data?
    ) throws -> String {
        guard privateKey.count >= 2 else {
            throw SaQuraError.invalidKey("Invalid Gen4 private key")
        }

        guard let encapsulatedSecret = secret, !encapsulatedSecret.isEmpty else {
            throw SaQuraError.invalidInput("Encapsulated secret required for Gen4 decryption")
        }

        // Minimum: Nonce(12) + Tag(16) = 28
        guard encryptedMessage.count >= 28 else {
            throw SaQuraError.invalidInput("Invalid Gen4 encrypted message")
        }

        // Extract raw secret key (skip 2-byte header)
        let rawSecretKey = Data(privateKey.suffix(from: 2))

        // Decapsulate using FrodoKEM-1344-AES
        let kem = try OQSKem(algorithm: .frodokem1344aes)
        let sharedSecret = try kem.decapsulate(ciphertext: encapsulatedSecret, secretKey: rawSecretKey)

        // Custom KDF: HMAC-SHA256(key=sharedSecret, data=[0x01]).prefix(32)
        let hmacKey = SymmetricKey(data: sharedSecret)
        let kdfInput = Data([0x01])
        let derivedKeyData = Data(HMAC<SHA256>.authenticationCode(for: kdfInput, using: hmacKey))
        let symmetricKey = SymmetricKey(data: derivedKeyData.prefix(32))

        // Parse encrypted message: [Nonce:12][Ciphertext:N][Tag:16]
        let nonce = encryptedMessage.prefix(12)
        let tag = encryptedMessage.suffix(16)
        let ciphertext = encryptedMessage.dropFirst(12).dropLast(16)

        // Decrypt
        do {
            let gcmNonce = try AES.GCM.Nonce(data: nonce)
            let sealedBox = try AES.GCM.SealedBox(nonce: gcmNonce, ciphertext: ciphertext, tag: tag)
            let decryptedData = try AES.GCM.open(sealedBox, using: symmetricKey)

            guard let plaintext = String(data: decryptedData, encoding: .utf8) else {
                throw SaQuraError.decryptionFailed("Failed to decode as UTF-8")
            }
            return plaintext
        } catch let error as SaQuraError {
            throw error
        } catch {
            throw SaQuraError.decryptionFailed("AES-GCM decryption failed: \(error.localizedDescription)")
        }
    }
}
