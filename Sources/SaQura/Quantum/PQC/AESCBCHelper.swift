// AESCBCHelper.swift
// SaQura Swift Library
// Copyright (c) 2025-2026 KyotoTech LLC. All rights reserved.

import Foundation
import CommonCrypto

/// AES-256-CBC encryption/decryption with PKCS7 padding via CommonCrypto
/// Used by Gen2 and Gen5 for .NET compatibility
internal struct AESCBCHelper {

    /// Encrypts plaintext using AES-256-CBC with PKCS7 padding
    /// - Parameters:
    ///   - plaintext: The data to encrypt
    ///   - key: 32-byte AES-256 key
    ///   - iv: 16-byte initialization vector
    /// - Returns: The ciphertext (without IV prefix)
    static func encrypt(plaintext: Data, key: Data, iv: Data) throws -> Data {
        guard key.count == kCCKeySizeAES256 else {
            throw SaQuraError.encryptionFailed("AES-CBC key must be 32 bytes, got \(key.count)")
        }
        guard iv.count == kCCBlockSizeAES128 else {
            throw SaQuraError.encryptionFailed("AES-CBC IV must be 16 bytes, got \(iv.count)")
        }

        // Output buffer: plaintext + one full block for padding
        let bufferSize = plaintext.count + kCCBlockSizeAES128
        var ciphertext = Data(count: bufferSize)
        var bytesEncrypted = 0

        let status = ciphertext.withUnsafeMutableBytes { ctPtr in
            plaintext.withUnsafeBytes { ptPtr in
                key.withUnsafeBytes { keyPtr in
                    iv.withUnsafeBytes { ivPtr in
                        CCCrypt(
                            CCOperation(kCCEncrypt),
                            CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(kCCOptionPKCS7Padding),
                            keyPtr.baseAddress, key.count,
                            ivPtr.baseAddress,
                            ptPtr.baseAddress, plaintext.count,
                            ctPtr.baseAddress, bufferSize,
                            &bytesEncrypted
                        )
                    }
                }
            }
        }

        guard status == kCCSuccess else {
            throw SaQuraError.encryptionFailed("AES-CBC encryption failed with status \(status)")
        }

        ciphertext.removeSubrange(bytesEncrypted..<ciphertext.count)
        return ciphertext
    }

    /// Decrypts ciphertext using AES-256-CBC with PKCS7 padding
    /// - Parameters:
    ///   - ciphertext: The data to decrypt (without IV prefix)
    ///   - key: 32-byte AES-256 key
    ///   - iv: 16-byte initialization vector
    /// - Returns: The decrypted plaintext
    static func decrypt(ciphertext: Data, key: Data, iv: Data) throws -> Data {
        guard key.count == kCCKeySizeAES256 else {
            throw SaQuraError.decryptionFailed("AES-CBC key must be 32 bytes, got \(key.count)")
        }
        guard iv.count == kCCBlockSizeAES128 else {
            throw SaQuraError.decryptionFailed("AES-CBC IV must be 16 bytes, got \(iv.count)")
        }

        let bufferSize = ciphertext.count + kCCBlockSizeAES128
        var plaintext = Data(count: bufferSize)
        var bytesDecrypted = 0

        let status = plaintext.withUnsafeMutableBytes { ptPtr in
            ciphertext.withUnsafeBytes { ctPtr in
                key.withUnsafeBytes { keyPtr in
                    iv.withUnsafeBytes { ivPtr in
                        CCCrypt(
                            CCOperation(kCCDecrypt),
                            CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(kCCOptionPKCS7Padding),
                            keyPtr.baseAddress, key.count,
                            ivPtr.baseAddress,
                            ctPtr.baseAddress, ciphertext.count,
                            ptPtr.baseAddress, bufferSize,
                            &bytesDecrypted
                        )
                    }
                }
            }
        }

        guard status == kCCSuccess else {
            throw SaQuraError.decryptionFailed("AES-CBC decryption failed with status \(status)")
        }

        plaintext.removeSubrange(bytesDecrypted..<plaintext.count)
        return plaintext
    }
}
