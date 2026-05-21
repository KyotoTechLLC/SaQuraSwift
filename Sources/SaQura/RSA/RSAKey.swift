// RSAKey.swift
// SaQura Swift Library
// Copyright (c) 2025-2026 KyotoTech LLC. All rights reserved.

import Foundation
import Security

/// Generates and manages RSA-4096 key pairs
public struct RSAKey {
    /// RSA key size in bits
    public static let keySize = 4096

    /// Generates a new RSA-4096 key pair
    /// - Returns: Tuple containing (privateKey, publicKey) in PEM format
    public static func newKeyPair() async throws -> (privateKey: String, publicKey: String) {
        return try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    let keyPair = try generateKeyPair()
                    continuation.resume(returning: keyPair)
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    /// Generates RSA key pair synchronously
    private static func generateKeyPair() throws -> (privateKey: String, publicKey: String) {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: keySize,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: false
            ]
        ]

        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw SaQuraError.keyGenerationFailed(error?.takeRetainedValue().localizedDescription ?? "Unknown error")
        }

        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw SaQuraError.keyGenerationFailed("Failed to extract public key")
        }

        // Export to PEM
        let privateKeyPEM = try exportPrivateKeyToPEM(privateKey)
        let publicKeyPEM = try exportPublicKeyToPEM(publicKey)

        return (privateKeyPEM, publicKeyPEM)
    }

    // MARK: - PEM Export

    /// Exports private key to PEM format
    private static func exportPrivateKeyToPEM(_ key: SecKey) throws -> String {
        var error: Unmanaged<CFError>?
        guard let data = SecKeyCopyExternalRepresentation(key, &error) as Data? else {
            throw SaQuraError.keyGenerationFailed("Failed to export private key: \(error?.takeRetainedValue().localizedDescription ?? "Unknown")")
        }

        // Wrap in PKCS#8 format for .NET compatibility
        let pkcs8Data = wrapInPKCS8(data)
        let base64 = pkcs8Data.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])

        return """
        -----BEGIN PRIVATE KEY-----
        \(base64)
        -----END PRIVATE KEY-----
        """
    }

    /// Exports public key to PEM format
    private static func exportPublicKeyToPEM(_ key: SecKey) throws -> String {
        var error: Unmanaged<CFError>?
        guard let data = SecKeyCopyExternalRepresentation(key, &error) as Data? else {
            throw SaQuraError.keyGenerationFailed("Failed to export public key: \(error?.takeRetainedValue().localizedDescription ?? "Unknown")")
        }

        // Wrap in SPKI format for .NET compatibility
        let spkiData = wrapInSPKI(data)
        let base64 = spkiData.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])

        return """
        -----BEGIN PUBLIC KEY-----
        \(base64)
        -----END PUBLIC KEY-----
        """
    }

    // MARK: - Key Validation

    /// Validates if a string is a valid RSA private key in PEM format
    public static func isValidPrivateKey(_ pem: String) -> Bool {
        return importPrivateKey(from: pem) != nil
    }

    /// Validates if a string is a valid RSA public key in PEM format
    public static func isValidPublicKey(_ pem: String) -> Bool {
        return importPublicKey(from: pem) != nil
    }

    /// Extracts public key from private key
    public static func getPublicKey(from privateKeyPEM: String) throws -> String {
        guard let privateKey = importPrivateKey(from: privateKeyPEM) else {
            throw SaQuraError.invalidKey("Invalid private key")
        }

        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw SaQuraError.invalidKey("Failed to extract public key")
        }

        return try exportPublicKeyToPEM(publicKey)
    }

    // MARK: - Key Import

    /// Imports a private key from PEM format.
    ///
    /// Accepts both `-----BEGIN PRIVATE KEY-----` (PKCS#8) and
    /// `-----BEGIN RSA PRIVATE KEY-----` (PKCS#1) PEM headers. For raw
    /// PKCS#1 DER input, falls back to wrapping in PKCS#8 if Apple's
    /// `SecKeyCreateWithData` rejects the direct form.
    internal static func importPrivateKey(from pem: String) -> SecKey? {
        // Try both PEM headers: PKCS#8 first, then PKCS#1 fallback.
        var pemContent = extractPEMContent(pem, type: "PRIVATE KEY")
        if pemContent.isEmpty {
            pemContent = extractPEMContent(pem, type: "RSA PRIVATE KEY")
        }
        guard let data = Data(base64Encoded: pemContent, options: .ignoreUnknownCharacters) else {
            return nil
        }

        // If input is PKCS#8, unwrap to raw PKCS#1; otherwise use as-is.
        let keyData = unwrapPKCS8(data) ?? data

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits as String: keySize
        ]

        // Try direct first — `SecKeyCreateWithData` accepts raw PKCS#1
        // RSAPrivateKey DER per Apple docs on most macOS / iOS versions.
        var error: Unmanaged<CFError>?
        if let key = SecKeyCreateWithData(keyData as CFData, attributes as CFDictionary, &error) {
            return key
        }

        // Fallback for environments where the direct PKCS#1 path is
        // rejected: wrap in PKCS#8 envelope and retry. Same workaround
        // pattern as `LicenseValidator.importPublicKey`'s SPKI fallback.
        let pkcs8Data = wrapInPKCS8(keyData)
        return SecKeyCreateWithData(pkcs8Data as CFData, attributes as CFDictionary, nil)
    }

    /// Imports a public key from PEM format.
    ///
    /// Accepts both `-----BEGIN PUBLIC KEY-----` (SPKI/PKCS#8-wrapped) and
    /// `-----BEGIN RSA PUBLIC KEY-----` (raw PKCS#1) PEM headers. For raw
    /// PKCS#1 DER input, falls back to wrapping in SPKI if Apple's
    /// `SecKeyCreateWithData` rejects the direct form. This matches the
    /// SPKI-wrap fallback used by `LicenseValidator.importPublicKey`.
    internal static func importPublicKey(from pem: String) -> SecKey? {
        // Try both PEM headers: SPKI first, then PKCS#1 fallback.
        var pemContent = extractPEMContent(pem, type: "PUBLIC KEY")
        if pemContent.isEmpty {
            pemContent = extractPEMContent(pem, type: "RSA PUBLIC KEY")
        }

        guard let data = Data(base64Encoded: pemContent, options: .ignoreUnknownCharacters) else {
            return nil
        }

        // If input is SPKI, unwrap to raw PKCS#1; otherwise use as-is.
        let keyData = unwrapSPKI(data) ?? data

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: keySize
        ]

        // Try direct first.
        var error: Unmanaged<CFError>?
        if let key = SecKeyCreateWithData(keyData as CFData, attributes as CFDictionary, &error) {
            return key
        }

        // Fallback for environments where `SecKeyCreateWithData` rejects
        // raw PKCS#1 DER for RSA public keys: wrap in SPKI and retry.
        // Uses the existing `wrapInSPKI` helper defined below — same
        // ASN.1 layout `LicenseValidator.wrapPKCS1InSPKI` uses.
        let spkiData = wrapInSPKI(keyData)
        return SecKeyCreateWithData(spkiData as CFData, attributes as CFDictionary, nil)
    }

    // MARK: - PEM Helpers

    /// Extracts base64 content from PEM
    private static func extractPEMContent(_ pem: String, type: String) -> String {
        return pem
            .replacingOccurrences(of: "-----BEGIN \(type)-----", with: "")
            .replacingOccurrences(of: "-----END \(type)-----", with: "")
            .replacingOccurrences(of: "\n", with: "")
            .replacingOccurrences(of: "\r", with: "")
            .trimmingCharacters(in: .whitespaces)
    }

    // MARK: - ASN.1 Wrappers

    /// Wraps RSA private key in PKCS#8 format
    private static func wrapInPKCS8(_ keyData: Data) -> Data {
        // RSA OID: 1.2.840.113549.1.1.1
        let rsaOID: [UInt8] = [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00]

        var pkcs8 = Data()

        // Build algorithm identifier sequence
        var algorithmId = Data([0x30])
        algorithmId.append(contentsOf: encodeLength(rsaOID.count))
        algorithmId.append(contentsOf: rsaOID)

        // Build octet string for key data
        var octetString = Data([0x04])
        octetString.append(contentsOf: encodeLength(keyData.count))
        octetString.append(keyData)

        // Build version
        let version = Data([0x02, 0x01, 0x00])

        // Total sequence length
        let totalLength = version.count + algorithmId.count + octetString.count

        // Build outer sequence
        pkcs8.append(0x30)
        pkcs8.append(contentsOf: encodeLength(totalLength))
        pkcs8.append(version)
        pkcs8.append(algorithmId)
        pkcs8.append(octetString)

        return pkcs8
    }

    /// Wraps RSA public key in SPKI format
    private static func wrapInSPKI(_ keyData: Data) -> Data {
        // RSA OID: 1.2.840.113549.1.1.1
        let rsaOID: [UInt8] = [0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00]

        var spki = Data()

        // Calculate lengths
        let bitStringLength = keyData.count + 1 // +1 for unused bits byte
        let sequenceLength = rsaOID.count + encodeLength(bitStringLength).count + 1 + bitStringLength

        // Outer SEQUENCE
        spki.append(0x30)
        spki.append(contentsOf: encodeLength(sequenceLength))

        // Algorithm identifier
        spki.append(contentsOf: rsaOID)

        // BIT STRING containing public key
        spki.append(0x03)
        spki.append(contentsOf: encodeLength(bitStringLength))
        spki.append(0x00) // unused bits

        // Public key data
        spki.append(keyData)

        return spki
    }

    /// Unwraps PKCS#8 to get raw key data
    private static func unwrapPKCS8(_ data: Data) -> Data? {
        // Check if it's PKCS#8 format (starts with SEQUENCE)
        guard data.count > 26, data[0] == 0x30 else { return nil }

        // Skip version (3 bytes) and algorithm identifier (~15 bytes)
        // Find the OCTET STRING (0x04)
        for i in 20..<min(30, data.count) {
            if data[i] == 0x04 {
                let (length, offset) = decodeLength(data, at: i + 1)
                if length > 0 && i + 1 + offset + length <= data.count {
                    return Data(data[(i + 1 + offset)..<(i + 1 + offset + length)])
                }
            }
        }

        return nil
    }

    /// Unwraps SPKI to get raw key data
    private static func unwrapSPKI(_ data: Data) -> Data? {
        // Check if it's SPKI format (starts with SEQUENCE)
        guard data.count > 20, data[0] == 0x30 else { return nil }

        // Find the BIT STRING (0x03)
        for i in 10..<min(25, data.count) {
            if data[i] == 0x03 {
                let (length, offset) = decodeLength(data, at: i + 1)
                if length > 1 && i + 1 + offset + length <= data.count {
                    // Skip the unused bits byte
                    return Data(data[(i + 2 + offset)..<(i + 1 + offset + length)])
                }
            }
        }

        return nil
    }

    /// Encodes ASN.1 length
    private static func encodeLength(_ length: Int) -> [UInt8] {
        if length < 128 {
            return [UInt8(length)]
        } else if length < 256 {
            return [0x81, UInt8(length)]
        } else if length < 65536 {
            return [0x82, UInt8(length >> 8), UInt8(length & 0xFF)]
        } else {
            return [0x83, UInt8(length >> 16), UInt8((length >> 8) & 0xFF), UInt8(length & 0xFF)]
        }
    }

    /// Decodes ASN.1 length
    private static func decodeLength(_ data: Data, at index: Int) -> (length: Int, bytesUsed: Int) {
        guard index < data.count else { return (0, 0) }

        let firstByte = data[index]
        if firstByte < 128 {
            return (Int(firstByte), 1)
        }

        let numBytes = Int(firstByte & 0x7F)
        guard index + numBytes < data.count else { return (0, 0) }

        var length = 0
        for i in 0..<numBytes {
            length = (length << 8) | Int(data[index + 1 + i])
        }

        return (length, numBytes + 1)
    }
}
