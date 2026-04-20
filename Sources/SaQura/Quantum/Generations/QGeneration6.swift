// QGeneration6.swift
// SaQura Swift Library
// Copyright (c) 2025-2026 KyotoTech LLC. All rights reserved.

import Foundation
import CryptoKit

/// Generation 6: FrodoKEM (strength-based) + HKDF-SHA256 + AES-256-GCM
/// Compatible with .NET SaQura QGeneration6
internal struct QGeneration6 {
    private static let generationByte: UInt8 = 0x06
    private static let hkdfInfo = Data("Gen6-Frodo-GCM".utf8)

    // MARK: - Key Generation

    /// Generates a Gen6 key pair using FrodoKEM (640/976/1344 based on strength)
    /// Header: [0x06][Strength][RawPublicKey...]
    static func generateKeyPair(strength: QuantumStrength) throws -> (publicKey: Data, privateKey: Data) {
        let kem = try FrodoKEMHelper.createKem(for: strength)
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

    /// Encrypts a message using Gen6: FrodoKEM encapsulation + HKDF + AES-GCM
    /// HKDF: SHA256, salt=random16, info="Gen6-Frodo-GCM"
    /// Combined wire: [EncapsLen:4_LE][Encapsulated][Salt:16][Nonce:12][Ciphertext][Tag:16]
    /// Separate output: encapsulated = raw capsule, encrypted = [Salt:16][Nonce:12][CT][Tag:16]
    static func encrypt(
        _ message: String,
        publicKey: Data
    ) throws -> (encapsulatedSecret: Data, encryptedMessage: Data) {
        guard publicKey.count >= 2 else {
            throw SaQuraError.invalidKey("Invalid Gen6 public key")
        }

        // Extract strength and raw public key
        let strength = QuantumStrength(rawValue: publicKey[1]) ?? .standard
        let rawPublicKey = Data(publicKey.suffix(from: 2))

        // Encapsulate using FrodoKEM
        let kem = try FrodoKEMHelper.createKem(for: strength)
        let (ciphertext, sharedSecret) = try kem.encapsulate(publicKey: rawPublicKey)

        // HKDF-SHA256 key derivation
        let salt = Data.secureRandom(count: 16)
        let derivedKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: sharedSecret),
            salt: salt,
            info: hkdfInfo,
            outputByteCount: 32
        )

        // Encrypt with AES-256-GCM
        let messageData = Data(message.utf8)
        let nonce = AES.GCM.Nonce()

        guard let sealedBox = try? AES.GCM.seal(messageData, using: derivedKey, nonce: nonce) else {
            throw SaQuraError.encryptionFailed("AES-GCM encryption failed")
        }

        // Encapsulated: raw FrodoKEM capsule
        let encapsulatedSecret = ciphertext

        // Encrypted: [Salt:16][Nonce:12][Ciphertext][Tag:16]
        var encryptedMessage = Data()
        encryptedMessage.append(salt)
        encryptedMessage.append(contentsOf: nonce)
        encryptedMessage.append(sealedBox.ciphertext)
        encryptedMessage.append(sealedBox.tag)

        return (encapsulatedSecret, encryptedMessage)
    }

    /// Creates Gen6 combined format: [EncapsLen:4_LE][Encapsulated][Salt:16][Nonce:12][CT][Tag:16]
    /// This is the format .NET uses for the combined wire output
    static func encryptCombined(
        _ message: String,
        publicKey: Data
    ) throws -> Data {
        let (encapsulated, encrypted) = try encrypt(message, publicKey: publicKey)

        var combined = Data()
        // Encapsulated length as 4 bytes Little-Endian
        var encapsLen = UInt32(encapsulated.count).littleEndian
        combined.append(Data(bytes: &encapsLen, count: 4))
        combined.append(encapsulated)
        combined.append(encrypted)

        return combined
    }

    // MARK: - Decryption

    /// Decrypts a message using Gen6 algorithm
    static func decrypt(
        _ encryptedMessage: Data,
        privateKey: Data,
        secret: Data?
    ) throws -> String {
        guard privateKey.count >= 2 else {
            throw SaQuraError.invalidKey("Invalid Gen6 private key")
        }

        guard let encapsulatedSecret = secret, !encapsulatedSecret.isEmpty else {
            throw SaQuraError.invalidInput("Encapsulated secret required for Gen6 decryption")
        }

        // Minimum: Salt(16) + Nonce(12) + Tag(16) = 44
        guard encryptedMessage.count >= 44 else {
            throw SaQuraError.invalidInput("Invalid Gen6 encrypted message")
        }

        // Extract strength and raw secret key
        let strength = QuantumStrength(rawValue: privateKey[1]) ?? .standard
        let rawSecretKey = Data(privateKey.suffix(from: 2))

        // Decapsulate using FrodoKEM
        let kem = try FrodoKEMHelper.createKem(for: strength)
        let sharedSecret = try kem.decapsulate(ciphertext: encapsulatedSecret, secretKey: rawSecretKey)

        // Parse encrypted message: [Salt:16][Nonce:12][Ciphertext:N][Tag:16]
        let salt = Data(encryptedMessage.prefix(16))
        let nonce = Data(encryptedMessage[16..<28])
        let tag = Data(encryptedMessage.suffix(16))
        let ciphertext = Data(encryptedMessage[28..<(encryptedMessage.count - 16)])

        // HKDF-SHA256 key derivation
        let derivedKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: sharedSecret),
            salt: salt,
            info: hkdfInfo,
            outputByteCount: 32
        )

        // Decrypt
        do {
            let gcmNonce = try AES.GCM.Nonce(data: nonce)
            let sealedBox = try AES.GCM.SealedBox(nonce: gcmNonce, ciphertext: ciphertext, tag: tag)
            let decryptedData = try AES.GCM.open(sealedBox, using: derivedKey)

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

    /// Decrypts Gen6 combined format: [EncapsLen:4_LE][Encapsulated][Salt:16][Nonce:12][CT][Tag:16]
    static func decryptCombined(
        _ combinedData: Data,
        privateKey: Data
    ) throws -> String {
        guard combinedData.count >= 4 else {
            throw SaQuraError.invalidInput("Invalid Gen6 combined data")
        }

        // Read encapsulated length (4 bytes LE)
        let encapsLen = Int(combinedData.prefix(4).withUnsafeBytes { $0.loadUnaligned(as: UInt32.self).littleEndian })
        let encapsStart = 4
        let encapsEnd = encapsStart + encapsLen

        guard encapsEnd <= combinedData.count else {
            throw SaQuraError.invalidInput("Invalid Gen6 combined data format")
        }

        let encapsulated = Data(combinedData[encapsStart..<encapsEnd])
        let encrypted = Data(combinedData.suffix(from: encapsEnd))

        return try decrypt(encrypted, privateKey: privateKey, secret: encapsulated)
    }
}
