// QuantumTests.swift
// SaQura Swift Library Tests
// Copyright (c) 2025-2026 KyotoTech LLC. All rights reserved.

import XCTest
@testable import SaQura

final class QuantumTests: XCTestCase {

    // Force debug-mode bypass so Quantum crypto tests run identically
    // under `swift test` and `swift test -c release`. The license-gating
    // surface is verified separately by QuantumDefenseInDepthTests +
    // LicenseValidatorTests (which explicitly toggle the override).
    // Test-sweep 2026-05-12.
    override func setUp() { super.setUp(); debugModeOverride = true }
    override func tearDown() { debugModeOverride = nil; super.tearDown() }

    // MARK: - Key Generation Tests

    func testQuantumKeyGenerationGen2() async throws {
        let (publicKey, privateKey) = try await Quantum.generateKeyPair(
            strength: .standard,
            generation: .gen2
        )

        XCTAssertFalse(publicKey.isEmpty)
        XCTAssertFalse(privateKey.isEmpty)

        // Check generation byte
        XCTAssertEqual(publicKey[0], 0x02)
        XCTAssertEqual(privateKey[0], 0x02)

        // Check strength byte (standard = 0)
        XCTAssertEqual(publicKey[1], 0x00)
        XCTAssertEqual(privateKey[1], 0x00)
    }

    func testQuantumKeyGenerationGen4() async throws {
        let (publicKey, privateKey) = try await Quantum.generateKeyPair(
            strength: .standard,
            generation: .gen4
        )

        // Gen4 always uses Highest (0x02) regardless of input strength
        XCTAssertEqual(publicKey[0], 0x04)
        XCTAssertEqual(privateKey[0], 0x04)
        XCTAssertEqual(publicKey[1], 0x02) // Always Highest
    }

    func testQuantumKeyGenerationGen5() async throws {
        let (publicKey, privateKey) = try await Quantum.generateKeyPair(
            strength: .medium,
            generation: .gen5
        )

        XCTAssertEqual(publicKey[0], 0x05)
        XCTAssertEqual(privateKey[0], 0x05)
        XCTAssertEqual(publicKey[1], 0x01) // Medium
    }

    func testQuantumKeyGenerationGen6() async throws {
        let (publicKey, privateKey) = try await Quantum.generateKeyPair(
            strength: .standard,
            generation: .gen6
        )

        XCTAssertEqual(publicKey[0], 0x06)
        XCTAssertEqual(privateKey[0], 0x06)
        XCTAssertEqual(publicKey[1], 0x00) // Standard
    }

    func testQuantumKeyGenerationGen7() async throws {
        let (publicKey, privateKey) = try await Quantum.generateKeyPair(
            strength: .standard,
            generation: .gen7
        )

        XCTAssertEqual(publicKey[0], 0x07)
        XCTAssertEqual(privateKey[0], 0x07)

        // Verify RSA key length field is 4 bytes LE at offset 2
        let rsaLen = publicKey[2..<6].withUnsafeBytes { $0.loadUnaligned(as: UInt32.self).littleEndian }
        XCTAssertGreaterThan(rsaLen, 0)
    }

    // MARK: - Gen4 Encryption/Decryption (FrodoKEM-1344 + GCM)

    func testQuantumEncryptDecryptGen4() async throws {
        let (publicKey, privateKey) = try await Quantum.generateKeyPair(
            strength: .standard,
            generation: .gen4
        )
        let message = "Gen4 FrodoKEM-1344 + AES-GCM test"

        let (secret, encrypted) = try await message.encryptWithQuantum(publicKey: publicKey)
        XCTAssertFalse(secret.isEmpty)
        XCTAssertFalse(encrypted.isEmpty)

        let decrypted = try await encrypted.decryptWithQuantum(privateKey: privateKey, secret: secret)
        XCTAssertEqual(decrypted, message)
    }

    // MARK: - Gen6 Encryption/Decryption (FrodoKEM + HKDF + GCM)

    func testQuantumEncryptDecryptGen6() async throws {
        let (publicKey, privateKey) = try await Quantum.generateKeyPair(
            strength: .standard,
            generation: .gen6
        )
        let message = "Gen6 FrodoKEM with HKDF + AES-GCM"

        let (secret, encrypted) = try await message.encryptWithQuantum(publicKey: publicKey)
        let decrypted = try await encrypted.decryptWithQuantum(privateKey: privateKey, secret: secret)
        XCTAssertEqual(decrypted, message)
    }

    func testQuantumEncryptDecryptGen6AllStrengths() async throws {
        for strength in QuantumStrength.allCases {
            let (publicKey, privateKey) = try await Quantum.generateKeyPair(
                strength: strength,
                generation: .gen6
            )
            let message = "Gen6 strength=\(strength.displayName)"

            let (secret, encrypted) = try await message.encryptWithQuantum(publicKey: publicKey)
            let decrypted = try await encrypted.decryptWithQuantum(privateKey: privateKey, secret: secret)
            XCTAssertEqual(decrypted, message, "Failed for strength \(strength.displayName)")
        }
    }

    // MARK: - Gen2 Encryption/Decryption (CMCE + CBC + HMAC)

    func testQuantumEncryptDecryptGen2() async throws {
        let (publicKey, privateKey) = try await Quantum.generateKeyPair(
            strength: .standard,
            generation: .gen2
        )
        let message = "Gen2 Classic McEliece + AES-CBC + HMAC"

        let (secret, encrypted) = try await message.encryptWithQuantum(publicKey: publicKey)
        let decrypted = try await encrypted.decryptWithQuantum(privateKey: privateKey, secret: secret)
        XCTAssertEqual(decrypted, message)
    }

    // MARK: - Gen5 Encryption/Decryption (CMCE + CBC + HMAC + Salt)

    func testQuantumEncryptDecryptGen5() async throws {
        let (publicKey, privateKey) = try await Quantum.generateKeyPair(
            strength: .standard,
            generation: .gen5
        )
        let message = "Gen5 CMCE + AES-CBC + HMAC with salt"

        let (secret, encrypted) = try await message.encryptWithQuantum(publicKey: publicKey)
        let decrypted = try await encrypted.decryptWithQuantum(privateKey: privateKey, secret: secret)
        XCTAssertEqual(decrypted, message)
    }

    // MARK: - Gen7 Encryption/Decryption (RSA + FrodoKEM Hybrid)

    func testQuantumEncryptDecryptGen7() async throws {
        let (publicKey, privateKey) = try await Quantum.generateKeyPair(
            strength: .standard,
            generation: .gen7
        )
        let message = "Gen7 hybrid RSA-4096 + FrodoKEM"

        let (secret, encrypted) = try await message.encryptWithQuantum(publicKey: publicKey)
        let decrypted = try await encrypted.decryptWithQuantum(privateKey: privateKey, secret: secret)
        XCTAssertEqual(decrypted, message)
    }

    // MARK: - Simplified API Tests

    func testQuantumEncryptToBytes() async throws {
        let (publicKey, privateKey) = try await Quantum.generateKeyPair(
            strength: .standard,
            generation: .gen6
        )
        let message = "Simplified API test"

        let encrypted = try await message.encryptWithQuantumToBytes(publicKey: publicKey)
        let decrypted = try await encrypted.decryptWithQuantum(privateKey: privateKey)

        XCTAssertEqual(decrypted, message)
    }

    func testQuantumEncryptToBytesGen4() async throws {
        let (publicKey, privateKey) = try await Quantum.generateKeyPair(
            strength: .standard,
            generation: .gen4
        )
        let message = "Gen4 simplified API"

        let encrypted = try await message.encryptWithQuantumToBytes(publicKey: publicKey)
        let decrypted = try await encrypted.decryptWithQuantum(privateKey: privateKey)

        XCTAssertEqual(decrypted, message)
    }

    // MARK: - Unicode Tests

    func testQuantumUnicodeGen4() async throws {
        let (publicKey, privateKey) = try await Quantum.generateKeyPair(
            strength: .standard,
            generation: .gen4
        )
        let message = "日本語テスト 🔐 Émojis & Ünïcödë"

        let (secret, encrypted) = try await message.encryptWithQuantum(publicKey: publicKey)
        let decrypted = try await encrypted.decryptWithQuantum(privateKey: privateKey, secret: secret)

        XCTAssertEqual(decrypted, message)
    }

    func testQuantumUnicodeGen6() async throws {
        let (publicKey, privateKey) = try await Quantum.generateKeyPair(
            strength: .standard,
            generation: .gen6
        )
        let message = "🇩🇪 Ährenfeld 🇯🇵 東京 🔑 Quantum-sicher!"

        let (secret, encrypted) = try await message.encryptWithQuantum(publicKey: publicKey)
        let decrypted = try await encrypted.decryptWithQuantum(privateKey: privateKey, secret: secret)

        XCTAssertEqual(decrypted, message)
    }

    // MARK: - Wire Format Tests

    func testGen4WireFormat() async throws {
        let (publicKey, _) = try await Quantum.generateKeyPair(
            strength: .standard,
            generation: .gen4
        )

        let (secret, encrypted) = try await "Test".encryptWithQuantum(publicKey: publicKey)

        // Encapsulated should be a FrodoKEM-1344 ciphertext
        // FrodoKEM-1344-AES ciphertext length is 21632 bytes
        XCTAssertEqual(secret.count, 21632, "FrodoKEM-1344-AES ciphertext should be 21632 bytes")

        // Encrypted: [Nonce:12][CT][Tag:16], minimum 28 bytes
        XCTAssertGreaterThanOrEqual(encrypted.count, 28)
    }

    func testGen6WireFormat() async throws {
        let (publicKey, _) = try await Quantum.generateKeyPair(
            strength: .standard,
            generation: .gen6
        )

        let (secret, encrypted) = try await "Test".encryptWithQuantum(publicKey: publicKey)

        // Encapsulated should be a FrodoKEM-640 ciphertext (standard strength)
        // FrodoKEM-640-AES ciphertext length is 9720 bytes
        XCTAssertEqual(secret.count, 9720, "FrodoKEM-640-AES ciphertext should be 9720 bytes")

        // Encrypted: [Salt:16][Nonce:12][CT][Tag:16], minimum 44 bytes
        XCTAssertGreaterThanOrEqual(encrypted.count, 44)
    }

    func testGen7WireFormat() async throws {
        let (publicKey, _) = try await Quantum.generateKeyPair(
            strength: .standard,
            generation: .gen7
        )

        let (secret, encrypted) = try await "Test".encryptWithQuantum(publicKey: publicKey)

        // Encapsulated: [RSAEncKeyLen:4_LE][RSAEncKey][FrodoCapsule]
        // RSA-4096 encrypted key is 512 bytes
        let rsaEncKeyLen = Int(secret.prefix(4).withUnsafeBytes { $0.loadUnaligned(as: UInt32.self).littleEndian })
        XCTAssertEqual(rsaEncKeyLen, 512, "RSA-4096 encrypted key should be 512 bytes")

        // Encrypted: [Salt:32][Nonce:12][CT][Tag:16], minimum 60 bytes
        XCTAssertGreaterThanOrEqual(encrypted.count, 60)
    }

    // MARK: - Generation Utility Tests

    func testRecommendedGeneration() {
        XCTAssertEqual(
            Quantum.getRecommendedGeneration(forMobile: true, highestSecurity: false),
            .gen6
        )
        XCTAssertEqual(
            Quantum.getRecommendedGeneration(forMobile: false, highestSecurity: false),
            .gen4
        )
        XCTAssertEqual(
            Quantum.getRecommendedGeneration(forMobile: false, highestSecurity: true),
            .gen7
        )
    }

    func testIsSecureGeneration() {
        XCTAssertFalse(Quantum.isSecureGeneration(.gen1))
        XCTAssertTrue(Quantum.isSecureGeneration(.gen2))
        XCTAssertFalse(Quantum.isSecureGeneration(.gen3))
        XCTAssertTrue(Quantum.isSecureGeneration(.gen4))
        XCTAssertTrue(Quantum.isSecureGeneration(.gen5))
        XCTAssertTrue(Quantum.isSecureGeneration(.gen6))
        XCTAssertTrue(Quantum.isSecureGeneration(.gen7))
    }

    func testSecurityAssessment() {
        let gen4Assessment = Quantum.getSecurityAssessment(.gen4)
        XCTAssertTrue(gen4Assessment.contains("SECURE"))
        XCTAssertTrue(gen4Assessment.contains("FrodoKEM"))

        let gen2Assessment = Quantum.getSecurityAssessment(.gen2)
        XCTAssertTrue(gen2Assessment.contains("SECURE"))
        XCTAssertTrue(gen2Assessment.contains("McEliece"))

        let gen1Assessment = Quantum.getSecurityAssessment(.gen1)
        XCTAssertTrue(gen1Assessment.contains("VULNERABLE"))
    }

    // MARK: - QuantumStrength Tests

    func testQuantumStrengthValues() {
        XCTAssertEqual(QuantumStrength.standard.rawValue, 0)
        XCTAssertEqual(QuantumStrength.medium.rawValue, 1)
        XCTAssertEqual(QuantumStrength.highest.rawValue, 2)

        // Verify 3 cases total (no more .light or .maximum)
        XCTAssertEqual(QuantumStrength.allCases.count, 3)
    }

    // MARK: - Error Handling Tests

    func testQuantumDecryptWithWrongKey() async throws {
        let (publicKey1, _) = try await Quantum.generateKeyPair(strength: .standard, generation: .gen4)
        let (_, privateKey2) = try await Quantum.generateKeyPair(strength: .standard, generation: .gen4)
        let message = "Secret"

        let (secret, encrypted) = try await message.encryptWithQuantum(publicKey: publicKey1)

        do {
            _ = try await encrypted.decryptWithQuantum(privateKey: privateKey2, secret: secret)
            XCTFail("Should have thrown an error")
        } catch {
            // Expected — wrong key should fail decryption.
            // Public surface from 1.0.6 onwards is QuantumOperationError; pre-existing
            // SaQuraError / OQSError are still acceptable for paths that don't pass
            // through the public Quantum.decrypt wrapper.
            XCTAssertTrue(
                error is QuantumOperationError ||
                error is SaQuraError ||
                error is OQSKem.OQSError,
                "Unexpected error type: \(type(of: error)) — \(error)"
            )
        }
    }

    // MARK: - Performance Tests

    func testQuantumGen6Performance() async throws {
        let (publicKey, privateKey) = try await Quantum.generateKeyPair(
            strength: .standard,
            generation: .gen6
        )
        let message = "Performance test message for Gen6 FrodoKEM"

        let start = Date()
        for _ in 0..<10 {
            let (secret, encrypted) = try await message.encryptWithQuantum(publicKey: publicKey)
            _ = try await encrypted.decryptWithQuantum(privateKey: privateKey, secret: secret)
        }
        let elapsed = Date().timeIntervalSince(start)

        // 10 encrypt/decrypt cycles should complete in under 2 seconds
        XCTAssertLessThan(elapsed, 2.0, "10 Gen6 encrypt/decrypt cycles took \(elapsed)s")
    }

    func testQuantumGen4Performance() async throws {
        let (publicKey, privateKey) = try await Quantum.generateKeyPair(
            strength: .standard,
            generation: .gen4
        )
        let message = "Performance test message for Gen4 FrodoKEM-1344"

        let start = Date()
        for _ in 0..<5 {
            let (secret, encrypted) = try await message.encryptWithQuantum(publicKey: publicKey)
            _ = try await encrypted.decryptWithQuantum(privateKey: privateKey, secret: secret)
        }
        let elapsed = Date().timeIntervalSince(start)

        // 5 Gen4 cycles should complete in under 5 seconds (FrodoKEM-1344 is slower)
        XCTAssertLessThan(elapsed, 5.0, "5 Gen4 encrypt/decrypt cycles took \(elapsed)s")
    }
}
