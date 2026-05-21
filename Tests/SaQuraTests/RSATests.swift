// RSATests.swift
// SaQura Swift Library Tests
// Copyright (c) 2025-2026 KyotoTech LLC. All rights reserved.

import XCTest
@testable import SaQura

final class RSATests: XCTestCase {

    // Force debug-mode bypass so RSA crypto tests run identically under
    // `swift test` and `swift test -c release`. Test-sweep 2026-05-12.
    override func setUp() { super.setUp(); debugModeOverride = true }
    override func tearDown() { debugModeOverride = nil; super.tearDown() }

    // MARK: - Key Generation Tests

    func testRSAKeyPairGeneration() async throws {
        let (privateKey, publicKey) = try await RSAKey.newKeyPair()

        XCTAssertFalse(privateKey.isEmpty)
        XCTAssertFalse(publicKey.isEmpty)

        // Verify PEM format
        XCTAssertTrue(privateKey.contains("-----BEGIN PRIVATE KEY-----"))
        XCTAssertTrue(privateKey.contains("-----END PRIVATE KEY-----"))
        XCTAssertTrue(publicKey.contains("-----BEGIN PUBLIC KEY-----"))
        XCTAssertTrue(publicKey.contains("-----END PUBLIC KEY-----"))
    }

    func testRSAKeyValidation() async throws {
        let (privateKey, publicKey) = try await RSAKey.newKeyPair()

        XCTAssertTrue(RSAKey.isValidPrivateKey(privateKey))
        XCTAssertTrue(RSAKey.isValidPublicKey(publicKey))
        XCTAssertFalse(RSAKey.isValidPrivateKey("invalid"))
        XCTAssertFalse(RSAKey.isValidPublicKey("invalid"))
    }

    func testRSAPublicKeyExtraction() async throws {
        let (privateKey, publicKey) = try await RSAKey.newKeyPair()

        let extractedPublicKey = try RSAKey.getPublicKey(from: privateKey)

        XCTAssertFalse(extractedPublicKey.isEmpty)
        XCTAssertTrue(extractedPublicKey.contains("-----BEGIN PUBLIC KEY-----"))
    }

    // MARK: - Encryption/Decryption Tests

    func testRSAEncryptDecryptString() async throws {
        let (privateKey, publicKey) = try await RSAKey.newKeyPair()
        let plaintext = "Hello, RSA!"

        let encrypted = try await plaintext.encryptWithRSA(publicKey: publicKey)
        XCTAssertFalse(encrypted.isEmpty)
        XCTAssertNotEqual(encrypted, plaintext)

        let decrypted = try await encrypted.decryptWithRSA(privateKey: privateKey)
        XCTAssertEqual(decrypted, plaintext)
    }

    func testRSAEncryptDecryptLargeData() async throws {
        let (privateKey, publicKey) = try await RSAKey.newKeyPair()
        // Large data should trigger hybrid encryption
        let plaintext = String(repeating: "Large data test. ", count: 100)

        let encrypted = try await plaintext.encryptWithRSA(publicKey: publicKey)
        let decrypted = try await encrypted.decryptWithRSA(privateKey: privateKey)

        XCTAssertEqual(decrypted, plaintext)
    }

    func testRSAHybridEncryption() async throws {
        let (privateKey, publicKey) = try await RSAKey.newKeyPair()
        // Data larger than 446 bytes triggers hybrid encryption
        let plaintext = String(repeating: "x", count: 1000)

        let encrypted = try await plaintext.encryptWithRSA(publicKey: publicKey)

        // Post-Sess-136: Swift hybrid wire format is the .NET canonical
        // layout `[KeyLen:4 LE = 512][EncKey:512][Nonce:12][Tag:16][CT:N]`.
        // The first four bytes encode 512 as little-endian uint32.
        let encryptedData = try XCTUnwrap(Data(base64Encoded: encrypted))
        let keyLen = encryptedData.prefix(4).withUnsafeBytes { $0.load(as: UInt32.self).littleEndian }
        XCTAssertEqual(keyLen, 512, "Hybrid wire format keyLen prefix should equal 512 (RSA-4096 ciphertext length)")
        XCTAssertNotEqual(encryptedData.prefix(4), Data([0x48, 0x59, 0x42, 0x52]), "Hybrid wire format should NOT start with legacy 'HYBR' magic post-Sess-136")

        let decrypted = try await encrypted.decryptWithRSA(privateKey: privateKey)
        XCTAssertEqual(decrypted, plaintext)
    }

    // MARK: - Signature Tests

    func testRSASignAndVerify() async throws {
        let (privateKey, publicKey) = try await RSAKey.newKeyPair()
        let message = "Sign this message"

        let signature = try await message.signWithRSA(privateKey: privateKey)
        XCTAssertFalse(signature.isEmpty)

        let isValid = try await message.verifyRSASignature(signature: signature, publicKey: publicKey)
        XCTAssertTrue(isValid)
    }

    func testRSASignatureInvalid() async throws {
        let (privateKey1, publicKey1) = try await RSAKey.newKeyPair()
        let (_, publicKey2) = try await RSAKey.newKeyPair()
        let message = "Sign this message"

        let signature = try await message.signWithRSA(privateKey: privateKey1)

        // Verify with wrong public key should fail
        let isValid = try await message.verifyRSASignature(signature: signature, publicKey: publicKey2)
        XCTAssertFalse(isValid)
    }

    func testRSASignatureTampered() async throws {
        let (privateKey, publicKey) = try await RSAKey.newKeyPair()
        let message = "Sign this message"

        let signature = try await message.signWithRSA(privateKey: privateKey)

        // Verify tampered message should fail
        let isValid = try await "Tampered message".verifyRSASignature(signature: signature, publicKey: publicKey)
        XCTAssertFalse(isValid)
    }

    // MARK: - Error Handling Tests

    func testRSADecryptWithWrongKey() async throws {
        let (privateKey1, publicKey1) = try await RSAKey.newKeyPair()
        let (privateKey2, _) = try await RSAKey.newKeyPair()
        let plaintext = "Hello"

        let encrypted = try await plaintext.encryptWithRSA(publicKey: publicKey1)

        do {
            _ = try await encrypted.decryptWithRSA(privateKey: privateKey2)
            XCTFail("Should have thrown an error")
        } catch {
            XCTAssertTrue(error is SaQuraError)
        }
    }

    // MARK: - Performance Tests

    func testRSAKeyGenerationPerformance() async throws {
        let start = Date()
        _ = try await RSAKey.newKeyPair()
        let elapsed = Date().timeIntervalSince(start)

        // RSA-4096 key generation should complete in under 5 seconds
        XCTAssertLessThan(elapsed, 5.0)
    }
}
