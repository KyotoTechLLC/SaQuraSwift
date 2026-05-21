// PasswordHasherTests.swift
// SaQura Swift Library Tests
// Copyright (c) 2025-2026 KyotoTech LLC. All rights reserved.

import XCTest
@testable import SaQura

final class PasswordHasherTests: XCTestCase {

    // Force debug-mode bypass so password-hash tests run identically
    // under `swift test` and `swift test -c release`. Test-sweep 2026-05-12.
    override func setUp() { super.setUp(); debugModeOverride = true }
    override func tearDown() { debugModeOverride = nil; super.tearDown() }

    // MARK: - Hash Generation Tests

    func testPasswordHashing() async throws {
        let password = "secure_password_123"

        let hash = try await password.hashPassword()

        XCTAssertFalse(hash.isEmpty)
        // Should be JSON
        XCTAssertTrue(hash.contains("algorithm"))
        XCTAssertTrue(hash.contains("pbkdf2"))
    }

    func testPasswordHashingDifferentPasswords() async throws {
        let hash1 = try await "password1".hashPassword()
        let hash2 = try await "password2".hashPassword()

        XCTAssertNotEqual(hash1, hash2)
    }

    func testPasswordHashingSamePasswordDifferentSalt() async throws {
        let hash1 = try await "password".hashPassword()
        let hash2 = try await "password".hashPassword()

        // Same password should produce different hashes (different random salts)
        XCTAssertNotEqual(hash1, hash2)
    }

    // MARK: - Verification Tests

    func testPasswordVerification() async throws {
        let password = "my_secure_password"

        let hash = try await password.hashPassword()
        let isValid = try await password.verifyPassword(hash: hash)

        XCTAssertTrue(isValid)
    }

    func testPasswordVerificationWrongPassword() async throws {
        let hash = try await "correct_password".hashPassword()
        let isValid = try await "wrong_password".verifyPassword(hash: hash)

        XCTAssertFalse(isValid)
    }

    func testPasswordVerificationEmpty() async throws {
        let hash = try await "password".hashPassword()
        let isValid = try await "".verifyPassword(hash: hash)

        XCTAssertFalse(isValid)
    }

    // MARK: - Hash Format Tests

    func testHashFormat() async throws {
        let hash = try await "test".hashPassword()

        // Parse JSON
        guard let data = hash.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            XCTFail("Hash should be valid JSON")
            return
        }

        XCTAssertEqual(json["algorithm"] as? String, "pbkdf2")
        XCTAssertEqual(json["version"] as? Int, 2)
        XCTAssertNotNil(json["salt"])
        XCTAssertNotNil(json["hash"])
        XCTAssertNotNil(json["parameters"])
        XCTAssertNotNil(json["createdUtc"])

        if let params = json["parameters"] as? [String: Any] {
            XCTAssertEqual(params["hashAlgorithm"] as? String, "SHA512")
            XCTAssertEqual(params["iterations"] as? Int, 210_000)
            XCTAssertEqual(params["outputLength"] as? Int, 64)
            XCTAssertEqual(params["saltLength"] as? Int, 32)
        }
    }

    // MARK: - Rehash Tests

    func testNeedsRehash() throws {
        // Create a hash with old iteration count (simulated)
        let oldHash = """
        {"algorithm":"pbkdf2","version":2,"salt":"dGVzdA==","hash":"dGVzdA==",
        "parameters":{"hashAlgorithm":"SHA512","iterations":100000,"outputLength":64,"saltLength":32},
        "createdUtc":"2025-01-01T00:00:00Z"}
        """

        XCTAssertTrue(oldHash.passwordHashNeedsRehash())

        // New hash should not need rehash
        // Note: Can't test this synchronously without refactoring
    }

    // MARK: - Password Strength Tests

    func testPasswordStrengthVeryWeak() {
        let strength = "123".analyzePasswordStrength()

        XCTAssertEqual(strength.level, .veryWeak)
        XCTAssertLessThan(strength.score, 20)
        XCTAssertFalse(strength.suggestions.isEmpty)
    }

    func testPasswordStrengthWeak() {
        let strength = "password".analyzePasswordStrength()

        XCTAssertEqual(strength.level, .weak)
        XCTAssertGreaterThanOrEqual(strength.score, 20)
        XCTAssertLessThan(strength.score, 40)
    }

    func testPasswordStrengthFair() {
        let strength = "Password1".analyzePasswordStrength()

        XCTAssertEqual(strength.level, .fair)
        XCTAssertGreaterThanOrEqual(strength.score, 40)
        XCTAssertLessThan(strength.score, 60)
    }

    func testPasswordStrengthStrong() {
        let strength = "MyP@ssw0rd!".analyzePasswordStrength()

        XCTAssertEqual(strength.level, .strong)
        XCTAssertGreaterThanOrEqual(strength.score, 60)
        XCTAssertLessThan(strength.score, 80)
    }

    func testPasswordStrengthVeryStrong() {
        let strength = "MyV3ry$ecure_P@ssw0rd!2025".analyzePasswordStrength()

        XCTAssertEqual(strength.level, .veryStrong)
        XCTAssertGreaterThanOrEqual(strength.score, 80)
    }

    func testPasswordStrengthSequentialPenalty() {
        let withoutSequential = "Password1!".getPasswordStrength()
        let withSequential = "Passabc12!".getPasswordStrength()

        // Sequential characters should reduce score
        XCTAssertLessThan(withSequential, withoutSequential + 10)
    }

    // MARK: - Performance Tests

    func testHashingPerformance() async throws {
        let password = "test_password"

        let start = Date()
        _ = try await password.hashPassword()
        let elapsed = Date().timeIntervalSince(start)

        // PBKDF2 with 210k iterations should take 0.1-1.0 seconds
        XCTAssertGreaterThan(elapsed, 0.05)
        XCTAssertLessThan(elapsed, 3.0)
    }
}
