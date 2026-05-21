// AESTests.swift
// SaQura Swift Library Tests
// Copyright (c) 2025-2026 KyotoTech LLC. All rights reserved.

import XCTest
@testable import SaQura

final class AESTests: XCTestCase {

    /// Force debug-mode behaviour so these crypto-logic tests run
    /// identically under `swift test` and `swift test -c release`. The
    /// license-gating surface (watermarks, size limits) is verified
    /// separately by the License + Quantum test files. Same pattern as
    /// the Kotlin AESTest.
    override func setUp() {
        super.setUp()
        debugModeOverride = true
    }

    override func tearDown() {
        debugModeOverride = nil
        super.tearDown()
    }

    // MARK: - Key Generation Tests

    func testAESKeyGeneration() {
        let key = AESKey.newKey()

        XCTAssertFalse(key.isEmpty)
        XCTAssert(AESKey.isValid(key))

        // Verify it's valid Base64
        XCTAssertNotNil(Data(base64Encoded: key))

        // Verify key size (32 bytes = 256 bits)
        if let keyData = Data(base64Encoded: key) {
            XCTAssertEqual(keyData.count, 32)
        }
    }

    func testAESKeyFromPassword() {
        let key = AESKey.deriveFromPassword("password123", salt: "mysalt", iterations: 100_000)

        XCTAssertNotNil(key)
        XCTAssert(AESKey.isValid(key!))

        // Same password + salt should produce same key
        let key2 = AESKey.deriveFromPassword("password123", salt: "mysalt", iterations: 100_000)
        XCTAssertEqual(key, key2)

        // Different salt should produce different key
        let key3 = AESKey.deriveFromPassword("password123", salt: "different", iterations: 100_000)
        XCTAssertNotEqual(key, key3)
    }

    // MARK: - Encryption/Decryption Tests

    func testAESEncryptDecryptString() async throws {
        let key = AESKey.newKey()
        let plaintext = "Hello, SaQura!"

        let encrypted = try await plaintext.encryptWithAES(key: key)
        XCTAssertFalse(encrypted.isEmpty)
        XCTAssertNotEqual(encrypted, plaintext)

        let decrypted = try await encrypted.decryptWithAES(key: key)
        XCTAssertEqual(decrypted, plaintext)
    }

    func testAESEncryptDecryptEmoji() async throws {
        let key = AESKey.newKey()
        let plaintext = "Hello 🔐 Secure 🛡️ World! 日本語テスト"

        let encrypted = try await plaintext.encryptWithAES(key: key)
        let decrypted = try await encrypted.decryptWithAES(key: key)

        XCTAssertEqual(decrypted, plaintext)
    }

    func testAESEncryptDecryptData() async throws {
        let key = AESKey.newKey()
        let plainData = Data("Binary test data".utf8)

        let encrypted = try await plainData.encryptWithAES(key: key)
        XCTAssertNotEqual(encrypted, plainData)

        let decrypted = try await encrypted.decryptWithAES(key: key)
        XCTAssertEqual(decrypted, plainData)
    }

    func testAESEncryptWithPassword() async throws {
        let password = "secure_password_123"
        let salt = "random_salt"
        let plaintext = "Secret message"

        let encrypted = try await plaintext.encryptWithPassword(password: password, salt: salt)
        let decrypted = try await encrypted.decryptWithPassword(password: password, salt: salt)

        XCTAssertEqual(decrypted, plaintext)
    }

    // MARK: - Error Handling Tests

    func testAESDecryptWithWrongKey() async throws {
        let key1 = AESKey.newKey()
        let key2 = AESKey.newKey()
        let plaintext = "Hello, World!"

        let encrypted = try await plaintext.encryptWithAES(key: key1)

        do {
            _ = try await encrypted.decryptWithAES(key: key2)
            XCTFail("Should have thrown an error")
        } catch {
            // Expected: decryption should fail with wrong key
            XCTAssertTrue(error is SaQuraError)
        }
    }

    func testAESDecryptInvalidData() async throws {
        let key = AESKey.newKey()
        let invalidData = "not_valid_base64!!!"

        do {
            _ = try await invalidData.decryptWithAES(key: key)
            XCTFail("Should have thrown an error")
        } catch {
            XCTAssertTrue(error is SaQuraError)
        }
    }

    // MARK: - Format Compatibility Tests

    func testAESOutputFormat() async throws {
        let key = AESKey.newKey()
        let plaintext = "Test"

        let encrypted = try await plaintext.encryptWithAES(key: key)

        // Should be valid Base64
        guard let encryptedData = Data(base64Encoded: encrypted) else {
            XCTFail("Encrypted output should be valid Base64")
            return
        }

        // Format: [Nonce:12][Ciphertext:N][Tag:16]
        // Minimum size: 12 + 1 + 16 = 29 bytes
        XCTAssertGreaterThanOrEqual(encryptedData.count, 29)

        // Nonce is always 12 bytes, tag is always 16 bytes
        // So ciphertext = total - 28
        let expectedCiphertextMinSize = 4 // "Test".utf8 = 4 bytes
        XCTAssertEqual(encryptedData.count, 12 + expectedCiphertextMinSize + 16)
    }

    // MARK: - Async Tests

    func testAESAsyncKeyGeneration() async {
        let key = await AESKey.newKeyAsync()
        XCTAssert(AESKey.isValid(key))
    }

    // MARK: - Performance Tests

    func testAESEncryptionPerformance() async throws {
        let key = AESKey.newKey()
        let plaintext = String(repeating: "x", count: 1000)

        let start = Date()
        for _ in 0..<100 {
            _ = try await plaintext.encryptWithAES(key: key)
        }
        let elapsed = Date().timeIntervalSince(start)

        // Should complete 100 encryptions in under 1 second
        XCTAssertLessThan(elapsed, 1.0)
    }
}
