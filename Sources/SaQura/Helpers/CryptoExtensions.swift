// CryptoExtensions.swift
// SaQura Swift Library
// Copyright (c) 2025-2026 KyotoTech LLC. All rights reserved.

import Foundation
import CryptoKit
import CommonCrypto

// MARK: - Data Extensions

public extension Data {
    /// Converts data to Base64 string
    func toBase64() -> String {
        return self.base64EncodedString()
    }

    /// Converts data to hexadecimal string
    func toHex() -> String {
        return self.map { String(format: "%02x", $0) }.joined().uppercased()
    }

    /// Computes SHA256 hash
    func sha256() -> Data {
        let digest = SHA256.hash(data: self)
        return Data(digest)
    }

    /// Computes SHA512 hash
    func sha512() -> Data {
        let digest = SHA512.hash(data: self)
        return Data(digest)
    }

    /// Computes HMAC-SHA256
    func hmacSHA256(key: Data) -> Data {
        let symmetricKey = SymmetricKey(data: key)
        let signature = HMAC<SHA256>.authenticationCode(for: self, using: symmetricKey)
        return Data(signature)
    }

    /// Computes HMAC-SHA512
    func hmacSHA512(key: Data) -> Data {
        let symmetricKey = SymmetricKey(data: key)
        let signature = HMAC<SHA512>.authenticationCode(for: self, using: symmetricKey)
        return Data(signature)
    }

    /// Generates cryptographically secure random bytes
    static func secureRandom(count: Int) -> Data {
        var data = Data(count: count)
        let result = data.withUnsafeMutableBytes { ptr in
            SecRandomCopyBytes(kSecRandomDefault, count, ptr.baseAddress!)
        }
        guard result == errSecSuccess else {
            fatalError("Failed to generate secure random bytes")
        }
        return data
    }

    /// Compares two data arrays in constant time (timing-attack safe)
    func secureCompare(_ other: Data) -> Bool {
        guard self.count == other.count else { return false }
        var diff: UInt8 = 0
        for (a, b) in zip(self, other) {
            diff |= a ^ b
        }
        return diff == 0
    }

    /// Securely zeros out the memory
    mutating func secureClear() {
        let byteCount = self.count
        self.withUnsafeMutableBytes { ptr in
            memset_s(ptr.baseAddress!, byteCount, 0, byteCount)
        }
    }
}

// MARK: - String Extensions

public extension String {
    /// Converts Base64 string to Data
    func fromBase64() -> Data? {
        return Data(base64Encoded: self)
    }

    /// Converts hex string to Data
    func fromHex() -> Data? {
        let hex = self.replacingOccurrences(of: " ", with: "")
            .replacingOccurrences(of: "-", with: "")
            .replacingOccurrences(of: ":", with: "")

        guard hex.count % 2 == 0 else { return nil }

        var data = Data()
        var index = hex.startIndex

        while index < hex.endIndex {
            let nextIndex = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<nextIndex], radix: 16) else {
                return nil
            }
            data.append(byte)
            index = nextIndex
        }

        return data
    }

    /// Encodes string to Base64
    func base64Encode() -> String {
        return Data(self.utf8).base64EncodedString()
    }

    /// Decodes Base64 string to plain text
    func base64Decode() -> String? {
        guard let data = Data(base64Encoded: self) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    /// Computes SHA256 hash of string
    func sha256() -> String {
        let data = Data(self.utf8)
        return data.sha256().toBase64()
    }

    /// Computes SHA512 hash of string
    func sha512() -> String {
        let data = Data(self.utf8)
        return data.sha512().toBase64()
    }

    /// Checks if string is valid Base64
    var isBase64: Bool {
        guard !self.isEmpty else { return false }
        return Data(base64Encoded: self) != nil
    }
}

// MARK: - Secure Memory Functions

/// Secure memset that won't be optimized away
@inline(never)
private func memset_s(_ dest: UnsafeMutableRawPointer?, _ destSize: Int, _ value: Int32, _ count: Int) {
    guard let dest = dest, count > 0 else { return }
    memset(dest, value, min(destSize, count))
    // Memory barrier to prevent optimization
    withExtendedLifetime(dest) {}
}

// MARK: - Utility Functions

public enum CryptoUtils {
    /// Generates cryptographically secure random bytes
    public static func generateRandomBytes(_ count: Int) -> Data {
        return Data.secureRandom(count: count)
    }

    /// Generates cryptographically secure random Base64 string
    public static func generateRandomBase64(byteLength: Int = 32) -> String {
        return Data.secureRandom(count: byteLength).toBase64()
    }

    /// Derives key from password using PBKDF2-SHA512
    public static func deriveKey(
        password: String,
        salt: Data,
        iterations: Int = 210_000,
        keyLength: Int = 32
    ) -> Data? {
        guard let passwordData = password.data(using: .utf8) else { return nil }

        var derivedKey = Data(count: keyLength)
        let result = derivedKey.withUnsafeMutableBytes { derivedKeyPtr in
            passwordData.withUnsafeBytes { passwordPtr in
                salt.withUnsafeBytes { saltPtr in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passwordPtr.baseAddress?.assumingMemoryBound(to: Int8.self),
                        passwordData.count,
                        saltPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        salt.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA512),
                        UInt32(iterations),
                        derivedKeyPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        keyLength
                    )
                }
            }
        }

        return result == kCCSuccess ? derivedKey : nil
    }
}
