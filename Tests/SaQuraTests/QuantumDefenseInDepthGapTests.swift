// QuantumDefenseInDepthGapTests.swift
// SaQura Swift Library Tests
// Copyright (c) 2025-2026 KyotoTech LLC. All rights reserved.

import XCTest
@testable import SaQura

/// Coverage gap-fill for the Swift 1.0.7 Defense-in-Depth surface.
/// Test-sweep 2026-05-12.
///
/// Companion to `QuantumDefenseInDepthTests`; this file covers boundary
/// cases (1-byte buffers), the security claim that the all-zero scan
/// short-circuits correctly (mostly-zero buffers must NOT trigger the
/// false-positive), output causality preservation, and the
/// generation/strength enum lookup edge cases.
final class QuantumDefenseInDepthGapTests: XCTestCase {

    // MARK: - 1-byte boundary

    func testEnsurePublicKeyAcceptsSingleNonZeroByte() throws {
        // Shortest valid input.
        XCTAssertNoThrow(try CallerInputValidator.ensurePublicKey(Data([0x42])))
    }

    func testEnsurePublicKeyRejectsSingleZeroByte() {
        // Shortest possible all-zero input still trips the check.
        XCTAssertThrowsError(try CallerInputValidator.ensurePublicKey(Data([0x00])))
    }

    func testEnsurePrivateKeyAcceptsSingleNonZeroByte() throws {
        XCTAssertNoThrow(try CallerInputValidator.ensurePrivateKey(Data([0x01])))
    }

    func testEnsureSecretAcceptsSingleNonZeroByte() throws {
        XCTAssertNoThrow(try CallerInputValidator.ensureSecret(Data([0x01])))
    }

    // MARK: - Mostly-zero short-circuit (security claim)

    func testEnsurePublicKeyAcceptsBufferWhereOnlyLastByteIsNonZero() throws {
        // The all-zero scan must NOT short-circuit out so eagerly that it
        // misses a non-zero byte at the end. Real keys often have
        // structured layout where one position can be the only non-zero
        // marker — this should still pass.
        var key = Data(count: 22 * 1024)
        key[key.count - 1] = 0x01
        XCTAssertNoThrow(try CallerInputValidator.ensurePublicKey(key))
    }

    func testEnsurePublicKeyAcceptsBufferWhereOnlyMiddleByteIsNonZero() throws {
        var key = Data(count: 22 * 1024)
        key[11 * 1024] = 0xFF
        XCTAssertNoThrow(try CallerInputValidator.ensurePublicKey(key))
    }

    func testEnsurePrivateKeyAcceptsBufferWhereOnlyMiddleByteIsNonZero() throws {
        var sk = Data(count: 16 * 1024)
        sk[8 * 1024] = 0x42
        XCTAssertNoThrow(try CallerInputValidator.ensurePrivateKey(sk))
    }

    func testEnsureSecretAcceptsBufferWhereOnlyLastByteIsNonZero() throws {
        var secret = Data(count: 32)
        secret[31] = 0x01
        XCTAssertNoThrow(try CallerInputValidator.ensureSecret(secret))
    }

    // MARK: - Output sanity-net cause preservation

    func testEnsureKeyGenOutputPreservesUnderlyingErrorForDiagnostics() {
        XCTAssertThrowsError(
            try CallerInputValidator.ensureKeyGenOutput(
                (publicKey: Data(), privateKey: Data([0x01])),
                generation: .gen5, strength: .highest
            )
        ) { error in
            guard case let QuantumOperationError.keyGeneration(_, _, underlying) = error else {
                XCTFail("Expected QuantumOperationError.keyGeneration, got \(error)")
                return
            }
            XCTAssertNotNil(underlying)
            // Inner error should be a SaQuraError.invalidInput with diagnostic message.
            guard case let SaQuraError.invalidInput(message) = underlying! else {
                XCTFail("Expected inner SaQuraError.invalidInput, got \(String(describing: underlying))")
                return
            }
            XCTAssertTrue(message.contains("regression in the cryptographic backend"), "Got: \(message)")
        }
    }

    func testEnsureEncryptOutputPreservesUnderlyingError() {
        XCTAssertThrowsError(
            try CallerInputValidator.ensureEncryptOutput(
                Data(), memberName: "encryptedMessage",
                generation: .gen4, strength: .standard
            )
        ) { error in
            guard case let QuantumOperationError.encryption(g, s, underlying) = error else {
                XCTFail("Expected QuantumOperationError.encryption, got \(error)")
                return
            }
            XCTAssertEqual(g, .gen4)
            XCTAssertEqual(s, .standard)
            XCTAssertNotNil(underlying)
        }
    }

    func testEnsureDecryptOutputPreservesUnderlyingError() {
        XCTAssertThrowsError(
            try CallerInputValidator.ensureDecryptOutput(nil, generation: .gen6, strength: .medium)
        ) { error in
            guard case let QuantumOperationError.decryption(_, _, underlying) = error else {
                XCTFail("Expected QuantumOperationError.decryption, got \(error)")
                return
            }
            XCTAssertNotNil(underlying)
            guard case let SaQuraError.invalidInput(message) = underlying! else {
                XCTFail("Expected inner SaQuraError.invalidInput, got \(String(describing: underlying))")
                return
            }
            XCTAssertTrue(message.contains("nil plaintext"), "Got: \(message)")
        }
    }

    // MARK: - generationFromKeyByte / strengthFromKeyByte edge cases

    func testGenerationFromKeyByteAllSevenGenerations() {
        for gen in QuantumGeneration.allCases {
            let key = Data([gen.rawValue])
            XCTAssertEqual(CallerInputValidator.generationFromKeyByte(key), gen)
        }
    }

    func testGenerationFromKeyByteCustomFallback() {
        // Unknown raw byte + custom fallback chain.
        let garbage = Data([42])
        XCTAssertEqual(CallerInputValidator.generationFromKeyByte(garbage, fallback: .gen6), .gen6)
        XCTAssertEqual(CallerInputValidator.generationFromKeyByte(garbage, fallback: .gen7), .gen7)
    }

    func testStrengthFromKeyByteAllThreeLevels() {
        let key1 = Data([QuantumGeneration.gen4.rawValue, QuantumStrength.standard.rawValue])
        let key2 = Data([QuantumGeneration.gen4.rawValue, QuantumStrength.medium.rawValue])
        let key3 = Data([QuantumGeneration.gen4.rawValue, QuantumStrength.highest.rawValue])

        XCTAssertEqual(CallerInputValidator.strengthFromKeyByte(key1), .standard)
        XCTAssertEqual(CallerInputValidator.strengthFromKeyByte(key2), .medium)
        XCTAssertEqual(CallerInputValidator.strengthFromKeyByte(key3), .highest)
    }

    func testStrengthFromKeyByteUnknownRawValueFallsBackToStandard() {
        let key = Data([QuantumGeneration.gen4.rawValue, 99])
        XCTAssertEqual(CallerInputValidator.strengthFromKeyByte(key), .standard)
    }

    // MARK: - QuantumGeneration enum completeness

    func testQuantumGenerationAllCasesCoverAllSevenWireValues() {
        XCTAssertEqual(QuantumGeneration.allCases.count, 7)
        let rawValues = QuantumGeneration.allCases.map { Int($0.rawValue) }.sorted()
        XCTAssertEqual(rawValues, [1, 2, 3, 4, 5, 6, 7])
    }

    func testQuantumGenerationDisplayNameNonEmpty() {
        for gen in QuantumGeneration.allCases {
            XCTAssertFalse(gen.displayName.isEmpty)
            XCTAssertFalse(gen.securityAssessment.isEmpty)
        }
    }

    func testQuantumGenerationRecommendedReplacementMatrix() {
        for gen in QuantumGeneration.allCases {
            if gen.isSecure {
                XCTAssertNil(gen.recommendedReplacement, "Secure \(gen) should not have a replacement")
            } else {
                XCTAssertNotNil(gen.recommendedReplacement, "Vulnerable \(gen) needs a recommended replacement")
                // The replacement must itself be secure.
                XCTAssertTrue(gen.recommendedReplacement!.isSecure)
            }
        }
    }

    func testQuantumStrengthSecurityBitsAreCanonical() {
        XCTAssertEqual(QuantumStrength.standard.securityBits, 128)
        XCTAssertEqual(QuantumStrength.medium.securityBits, 192)
        XCTAssertEqual(QuantumStrength.highest.securityBits, 256)
    }
}
