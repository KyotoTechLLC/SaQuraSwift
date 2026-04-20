// QGeneration7.swift
// SaQura Swift Library
// Copyright (c) 2025-2026 KyotoTech LLC. All rights reserved.

import Foundation
import CryptoKit
import Security

/// Generation 7: Hybrid RSA-4096 + FrodoKEM
/// Compatible with .NET SaQura QGeneration7
///
/// Key format: [0x07][Strength][RSAKeyLen:4_LE][RSAPubKey][FrodoPubKey]
/// Encrypt:
///   1. RSA-OAEP-SHA256 encrypts 32-byte session key
///   2. FrodoKEM encapsulation → shared secret
///   3. XOR mixing: combinedSecret[i] = sessionKey[i] ^ frodoSharedSecret[i % frodoSharedSecret.Length]
///   4. HKDF-SHA256(salt=random32, info="Gen7-Hybrid-RSA-Frodo") → AES-256-GCM
/// Encapsulated: [RSAEncKeyLen:4_LE][RSAEncryptedKey][FrodoCapsule]
/// Encrypted: [Salt:32][Nonce:12][Ciphertext][Tag:16]
///
/// IMPORTANT: RSA key length is 4 bytes Little-Endian (.NET BitConverter)
internal struct QGeneration7 {
    private static let generationByte: UInt8 = 0x07
    private static let rsaKeySize = 4096
    private static let hkdfInfo = Data("Gen7-Hybrid-RSA-Frodo".utf8)

    // MARK: - Key Generation

    /// Generates a Gen7 key pair (RSA-4096 + FrodoKEM)
    /// Format: [0x07][Strength][RSAKeyLen:4_LE][RSAPubKey][FrodoPubKey]
    static func generateKeyPair(strength: QuantumStrength) throws -> (publicKey: Data, privateKey: Data) {
        // Generate RSA-4096 key pair
        let rsaAttributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: rsaKeySize,
            kSecPrivateKeyAttrs as String: [kSecAttrIsPermanent as String: false]
        ]

        var error: Unmanaged<CFError>?
        guard let rsaPrivateKey = SecKeyCreateRandomKey(rsaAttributes as CFDictionary, &error) else {
            throw SaQuraError.keyGenerationFailed("RSA key generation failed")
        }

        guard let rsaPublicKey = SecKeyCopyPublicKey(rsaPrivateKey),
              let rsaPublicKeyData = SecKeyCopyExternalRepresentation(rsaPublicKey, nil) as Data?,
              let rsaPrivateKeyData = SecKeyCopyExternalRepresentation(rsaPrivateKey, nil) as Data? else {
            throw SaQuraError.keyGenerationFailed("Failed to export RSA keys")
        }

        // Generate FrodoKEM key pair
        let kem = try FrodoKEMHelper.createKem(for: strength)
        let (frodoPubKey, frodoSecKey) = try kem.generateKeyPair()

        // Format public key: [Gen:1][Strength:1][RSAKeyLen:4_LE][RSAPubKey][FrodoPubKey]
        var publicKeyResult = Data()
        publicKeyResult.append(generationByte)
        publicKeyResult.append(strength.rawValue)

        var rsaLength = UInt32(rsaPublicKeyData.count).littleEndian
        publicKeyResult.append(Data(bytes: &rsaLength, count: 4))
        publicKeyResult.append(rsaPublicKeyData)
        publicKeyResult.append(frodoPubKey)

        // Format private key: [Gen:1][Strength:1][RSAKeyLen:4_LE][RSAPrivKey][FrodoSecKey]
        var privateKeyResult = Data()
        privateKeyResult.append(generationByte)
        privateKeyResult.append(strength.rawValue)

        var rsaPrivLength = UInt32(rsaPrivateKeyData.count).littleEndian
        privateKeyResult.append(Data(bytes: &rsaPrivLength, count: 4))
        privateKeyResult.append(rsaPrivateKeyData)
        privateKeyResult.append(frodoSecKey)

        return (publicKeyResult, privateKeyResult)
    }

    // MARK: - Encryption

    /// Encrypts a message using Gen7 hybrid algorithm
    static func encrypt(
        _ message: String,
        publicKey: Data
    ) throws -> (encapsulatedSecret: Data, encryptedMessage: Data) {
        guard publicKey.count >= 6 else { // 1 + 1 + 4 (minimum header)
            throw SaQuraError.invalidKey("Invalid Gen7 public key")
        }

        // Extract strength
        let strength = QuantumStrength(rawValue: publicKey[1]) ?? .standard

        // Extract RSA public key length (4 bytes LE)
        let rsaLength = Int(publicKey[2..<6].withUnsafeBytes { $0.loadUnaligned(as: UInt32.self).littleEndian })
        let rsaStart = 6
        let rsaEnd = rsaStart + rsaLength

        guard rsaEnd <= publicKey.count else {
            throw SaQuraError.invalidKey("Invalid Gen7 public key: RSA key truncated")
        }

        let rsaPublicKeyData = Data(publicKey[rsaStart..<rsaEnd])
        let frodoPubKeyData = Data(publicKey.suffix(from: rsaEnd))

        // Import RSA public key
        let rsaAttributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: rsaKeySize
        ]

        var error: Unmanaged<CFError>?
        guard let rsaPublicKey = SecKeyCreateWithData(rsaPublicKeyData as CFData, rsaAttributes as CFDictionary, &error) else {
            throw SaQuraError.invalidKey("Invalid RSA public key")
        }

        // Step 1: RSA-OAEP-SHA256 encrypt a 32-byte session key
        let sessionKey = Data.secureRandom(count: 32)
        guard let rsaEncryptedKey = SecKeyCreateEncryptedData(
            rsaPublicKey,
            .rsaEncryptionOAEPSHA256,
            sessionKey as CFData,
            &error
        ) as Data? else {
            throw SaQuraError.encryptionFailed("RSA encryption failed")
        }

        // Step 2: FrodoKEM encapsulation
        let kem = try FrodoKEMHelper.createKem(for: strength)
        let (frodoCapsule, frodoSharedSecret) = try kem.encapsulate(publicKey: frodoPubKeyData)

        // Step 3: XOR mixing: combinedSecret[i] = sessionKey[i] ^ frodoSharedSecret[i % len]
        var combinedSecret = Data(count: 32)
        for i in 0..<32 {
            combinedSecret[i] = sessionKey[i] ^ frodoSharedSecret[i % frodoSharedSecret.count]
        }

        // Step 4: HKDF-SHA256(salt=random32, info="Gen7-Hybrid-RSA-Frodo") → AES key
        let salt = Data.secureRandom(count: 32)
        let derivedKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: combinedSecret),
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

        // Encapsulated: [RSAEncKeyLen:4_LE][RSAEncryptedKey][FrodoCapsule]
        var encapsulatedSecret = Data()
        var rsaEncKeyLen = UInt32(rsaEncryptedKey.count).littleEndian
        encapsulatedSecret.append(Data(bytes: &rsaEncKeyLen, count: 4))
        encapsulatedSecret.append(rsaEncryptedKey)
        encapsulatedSecret.append(frodoCapsule)

        // Encrypted: [Salt:32][Nonce:12][Ciphertext][Tag:16]
        var encryptedMessage = Data()
        encryptedMessage.append(salt)
        encryptedMessage.append(contentsOf: nonce)
        encryptedMessage.append(sealedBox.ciphertext)
        encryptedMessage.append(sealedBox.tag)

        return (encapsulatedSecret, encryptedMessage)
    }

    // MARK: - Decryption

    /// Decrypts a message using Gen7 hybrid algorithm
    static func decrypt(
        _ encryptedMessage: Data,
        privateKey: Data,
        secret: Data?
    ) throws -> String {
        guard privateKey.count >= 6 else {
            throw SaQuraError.invalidKey("Invalid Gen7 private key")
        }

        guard let encapsulatedSecret = secret, encapsulatedSecret.count >= 4 else {
            throw SaQuraError.invalidInput("Encapsulated secret required for Gen7 decryption")
        }

        // Minimum encrypted: Salt(32) + Nonce(12) + Tag(16) = 60
        guard encryptedMessage.count >= 60 else {
            throw SaQuraError.invalidInput("Invalid Gen7 encrypted message")
        }

        // Extract strength
        let strength = QuantumStrength(rawValue: privateKey[1]) ?? .standard

        // Extract RSA private key length (4 bytes LE)
        let rsaLength = Int(privateKey[2..<6].withUnsafeBytes { $0.loadUnaligned(as: UInt32.self).littleEndian })
        let rsaStart = 6
        let rsaEnd = rsaStart + rsaLength

        guard rsaEnd <= privateKey.count else {
            throw SaQuraError.invalidKey("Invalid Gen7 private key: RSA key truncated")
        }

        let rsaPrivateKeyData = Data(privateKey[rsaStart..<rsaEnd])
        let frodoSecKeyData = Data(privateKey.suffix(from: rsaEnd))

        // Import RSA private key
        let rsaAttributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits as String: rsaKeySize
        ]

        var error: Unmanaged<CFError>?
        guard let rsaPrivateKey = SecKeyCreateWithData(rsaPrivateKeyData as CFData, rsaAttributes as CFDictionary, &error) else {
            throw SaQuraError.invalidKey("Invalid RSA private key")
        }

        // Parse encapsulated secret: [RSAEncKeyLen:4_LE][RSAEncryptedKey][FrodoCapsule]
        let rsaEncKeyLen = Int(encapsulatedSecret.prefix(4).withUnsafeBytes { $0.loadUnaligned(as: UInt32.self).littleEndian })
        let rsaEncStart = 4
        let rsaEncEnd = rsaEncStart + rsaEncKeyLen

        guard rsaEncEnd <= encapsulatedSecret.count else {
            throw SaQuraError.invalidInput("Invalid Gen7 encapsulated secret: RSA encrypted key truncated")
        }

        let rsaEncryptedKey = Data(encapsulatedSecret[rsaEncStart..<rsaEncEnd])
        let frodoCapsule = Data(encapsulatedSecret.suffix(from: rsaEncEnd))

        // Step 1: Decrypt RSA session key
        guard let sessionKey = SecKeyCreateDecryptedData(
            rsaPrivateKey,
            .rsaEncryptionOAEPSHA256,
            rsaEncryptedKey as CFData,
            &error
        ) as Data? else {
            throw SaQuraError.decryptionFailed("RSA decryption failed")
        }

        // Step 2: FrodoKEM decapsulation
        let kem = try FrodoKEMHelper.createKem(for: strength)
        let frodoSharedSecret = try kem.decapsulate(ciphertext: frodoCapsule, secretKey: frodoSecKeyData)

        // Step 3: XOR mixing
        var combinedSecret = Data(count: 32)
        for i in 0..<32 {
            combinedSecret[i] = sessionKey[i] ^ frodoSharedSecret[i % frodoSharedSecret.count]
        }

        // Parse encrypted message: [Salt:32][Nonce:12][Ciphertext:N][Tag:16]
        let salt = Data(encryptedMessage.prefix(32))
        let nonce = Data(encryptedMessage[32..<44])
        let tag = Data(encryptedMessage.suffix(16))
        let ciphertext = Data(encryptedMessage[44..<(encryptedMessage.count - 16)])

        // Step 4: HKDF-SHA256
        let derivedKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: combinedSecret),
            salt: salt,
            info: hkdfInfo,
            outputByteCount: 32
        )

        // Decrypt with AES-256-GCM
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
}
