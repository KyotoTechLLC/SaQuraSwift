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

    /// Hybrid encryption: RSA-encrypted AES key + AES-GCM encrypted data.
    ///
    /// Wire format (.NET canonical):
    ///
    /// ```
    /// Offset  Length    Field
    /// 0       4         keyLen (uint32 little-endian) — always 512 for RSA-4096
    /// 4       512       encryptedAesKey   (RSA-4096 OAEP-SHA256 of the AES-256 key)
    /// 516     12        nonce             (AES-GCM IV)
    /// 528     16        tag               (AES-GCM authentication tag, separate
    ///                                      from ciphertext)
    /// 544     N         ciphertext        (AES-256-GCM(plaintext, key, nonce))
    /// ```
    ///
    /// Three changes vs pre-Sess-136 Swift format:
    ///  - No `HYBR` magic prefix (was `[HYBR:4]` at offset 0).
    ///  - KeyLen is **little-endian** (was big-endian).
    ///  - Tag comes **before** ciphertext (was after, via the AES-GCM
    ///    helper's `[Nonce][CT][Tag]` concat layout).
    ///
    /// Backwards-compat: existing Swift-encrypted hybrid data uses the
    /// old `HYBR`-prefixed format. The decrypt path is dual-shape and
    /// continues to read both via `legacyDecryptHybrid`.
    private static func encryptHybrid(_ data: Data, publicKey: SecKey) throws -> Data {
        // Generate random AES key, RSA-encrypt it.
        let aesKey = Data.secureRandom(count: 32)
        let encryptedKey = try encryptRSA(aesKey, publicKey: publicKey)
        precondition(encryptedKey.count == 512, "RSA-4096 OAEP-SHA256 ciphertext must be 512 bytes (got \(encryptedKey.count))")

        // AES-GCM-seal the plaintext directly via CryptoKit so we have
        // ciphertext + tag as separate values (the high-level helper would
        // concat them in `[Nonce][CT][Tag]` order which is the OLD Swift
        // hybrid layout — we need `[Nonce][Tag][CT]` to match .NET).
        let symmetricKey = SymmetricKey(data: aesKey)
        let sealedBox = try AES.GCM.seal(data, using: symmetricKey)
        let nonce = Data(sealedBox.nonce)
        let tag = sealedBox.tag
        let ciphertext = sealedBox.ciphertext

        var result = Data(capacity: 4 + encryptedKey.count + nonce.count + tag.count + ciphertext.count)
        // keyLen: 4 bytes little-endian, always 512.
        var keyLenLE = UInt32(encryptedKey.count).littleEndian
        result.append(Data(bytes: &keyLenLE, count: 4))
        result.append(encryptedKey)
        result.append(nonce)
        result.append(tag)
        result.append(ciphertext)
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

    /// Decrypts data with RSA or hybrid decryption. Dual-shape on the
    /// hybrid branch (.NET-canonical wire format):
    ///  - **New format** (.NET canonical): first 4 bytes are uint32 LE = 512.
    ///  - **Legacy Swift format**: first 4 bytes are `"HYBR"` (0x48 0x59 0x42 0x52).
    ///  - **Direct OAEP**: 512-byte ciphertext block, no prefix.
    ///
    /// The detection is unambiguous because the new-format keyLen (always
    /// 512 = 0x00 0x02 0x00 0x00 LE) cannot collide with the `HYBR` magic.
    static func decrypt(_ data: Data, privateKeyPEM: String) throws -> Data {
        guard let secKey = RSAKey.importPrivateKey(from: privateKeyPEM) else {
            throw SaQuraError.invalidKey("Invalid private key")
        }

        if data.count >= 8 && data.prefix(4) == hybridHeader {
            // Legacy Swift hybrid format from pre-Sess-136 — preserved for
            // backwards-compat with user data encrypted by older Swift libs.
            return try legacyDecryptHybrid(data, privateKey: secKey)
        }

        // Try new (.NET-canonical) hybrid format if the data is long enough
        // AND first 4 bytes as little-endian uint32 equal 512 (RSA-4096
        // block size).
        if data.count >= 4 + 512 + 12 + 16 {
            let keyLen = data.prefix(4).withUnsafeBytes { $0.loadUnaligned(as: UInt32.self).littleEndian }
            if keyLen == 512 {
                return try netDecryptHybrid(data, privateKey: secKey)
            }
        }
        return try decryptRSA(data, privateKey: secKey)
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

    /// Legacy Swift hybrid format (pre-Sess-136): `[HYBR:4][KeyLen:4 BE]
    /// [EncKey][Nonce:12][CT:N][Tag:16]`. Preserved so existing user data
    /// encrypted with older Swift libs continues to decrypt cleanly after
    /// the lib update. New encryptions use the .NET-canonical format
    /// produced by `encryptHybrid`.
    private static func legacyDecryptHybrid(_ data: Data, privateKey: SecKey) throws -> Data {
        let keyLengthBytes = data[4..<8]
        let keyLength = keyLengthBytes.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self).bigEndian }

        let keyStart = 8
        let keyEnd = keyStart + Int(keyLength)
        guard keyEnd < data.count else {
            throw SaQuraError.decryptionFailed("Invalid hybrid encrypted data (legacy Swift format)")
        }

        let encryptedKey = data[keyStart..<keyEnd]
        let encryptedData = data[keyEnd...]
        let aesKey = try decryptRSA(Data(encryptedKey), privateKey: privateKey)
        return try AESCryptographyHelper.decrypt(Data(encryptedData), key: aesKey.toBase64())
    }

    /// `.NET`-canonical hybrid format: `[KeyLen:4 LE = 512]
    /// [EncKey:512][Nonce:12][Tag:16][CT:N]`. Matches the spec v1.1 §5.2
    /// wire-format block and what HEAD .NET emits via
    /// `RsaCryptographyHelper.HybridEncryptAsync`.
    private static func netDecryptHybrid(_ data: Data, privateKey: SecKey) throws -> Data {
        // keyLen is the first 4 bytes LE; we already verified it == 512 in
        // the dispatch, but re-check for safety.
        let keyLen = Int(data.prefix(4).withUnsafeBytes { $0.loadUnaligned(as: UInt32.self).littleEndian })
        guard keyLen == 512 else {
            throw SaQuraError.decryptionFailed("Invalid hybrid encrypted data (keyLen=\(keyLen), expected 512)")
        }

        let nonceStart = 4 + keyLen     // 516
        let tagStart = nonceStart + 12  // 528
        let ctStart = tagStart + 16     // 544
        guard data.count >= ctStart else {
            throw SaQuraError.decryptionFailed("Invalid hybrid encrypted data (too short for .NET layout)")
        }

        let encryptedKey = Data(data[4..<nonceStart])
        let nonceBytes = Data(data[nonceStart..<tagStart])
        let tag = Data(data[tagStart..<ctStart])
        let ciphertext = Data(data[ctStart...])

        let aesKey = try decryptRSA(encryptedKey, privateKey: privateKey)

        do {
            let symmetricKey = SymmetricKey(data: aesKey)
            let gcmNonce = try AES.GCM.Nonce(data: nonceBytes)
            let sealedBox = try AES.GCM.SealedBox(nonce: gcmNonce, ciphertext: ciphertext, tag: tag)
            return try AES.GCM.open(sealedBox, using: symmetricKey)
        } catch {
            throw SaQuraError.decryptionFailed("Hybrid AES-GCM decryption failed: \(error.localizedDescription)")
        }
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
