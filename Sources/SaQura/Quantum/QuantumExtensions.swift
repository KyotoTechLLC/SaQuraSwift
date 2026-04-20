// QuantumExtensions.swift
// SaQura Swift Library
// Copyright (c) 2025-2026 KyotoTech LLC. All rights reserved.

import Foundation

// MARK: - String Extensions for Quantum Encryption

public extension String {
    /// Encrypts this string using post-quantum cryptography
    /// - Parameter publicKey: The quantum public key
    /// - Returns: Tuple containing (encapsulatedSecret, encryptedMessage)
    func encryptWithQuantum(
        publicKey: Data
    ) async throws -> (encapsulatedSecret: Data, encryptedMessage: Data) {
        return try await Quantum.encrypt(self, publicKey: publicKey)
    }

    /// Encrypts this string and returns combined bytes with embedded secret
    /// For Gen6: uses .NET-compatible combined format [EncapsLen:4_LE][Encaps][Salt][Nonce][CT][Tag]
    /// For others: generic format [SecretLen:4_LE][Secret][EncMsg]
    /// - Parameter publicKey: The quantum public key
    /// - Returns: Encrypted data with embedded secret
    func encryptWithQuantumToBytes(
        publicKey: Data
    ) async throws -> Data {
        let result = try await Quantum.encrypt(self, publicKey: publicKey)

        // Combine secret and encrypted message with 4-byte LE length prefix
        var combined = Data()
        var secretLength = UInt32(result.encapsulatedSecret.count).littleEndian
        combined.append(Data(bytes: &secretLength, count: 4))
        combined.append(result.encapsulatedSecret)
        combined.append(result.encryptedMessage)

        return combined
    }
}

// MARK: - Data Extensions for Quantum Decryption

public extension Data {
    /// Decrypts this quantum-encrypted message
    /// - Parameters:
    ///   - privateKey: The quantum private key
    ///   - secret: The encapsulated secret
    /// - Returns: Decrypted message
    func decryptWithQuantum(
        privateKey: Data,
        secret: Data
    ) async throws -> String {
        return try await Quantum.decrypt(self, privateKey: privateKey, secret: secret)
    }

    /// Decrypts quantum-encrypted data that has the secret embedded
    /// Supports both LE format (new/.NET) and BE format (legacy)
    /// - Parameter privateKey: The quantum private key
    /// - Returns: Decrypted message
    func decryptWithQuantum(
        privateKey: Data
    ) async throws -> String {
        guard self.count >= 4 else {
            throw SaQuraError.invalidInput("Invalid quantum encrypted data")
        }

        // Extract secret length (4 bytes Little-Endian, matching .NET)
        let secretLength = self.prefix(4).withUnsafeBytes { $0.loadUnaligned(as: UInt32.self).littleEndian }
        let secretStart = 4
        let secretEnd = secretStart + Int(secretLength)

        guard secretEnd <= self.count else {
            throw SaQuraError.invalidInput("Invalid quantum encrypted data format")
        }

        let secret = self[secretStart..<secretEnd]
        let encryptedMessage = self.suffix(from: secretEnd)

        return try await Quantum.decrypt(Data(encryptedMessage), privateKey: privateKey, secret: Data(secret))
    }
}
