// QuantumDefenseInDepthTests.swift
// SaQura Swift Library Tests
// Copyright (c) 2025-2026 KyotoTech LLC. All rights reserved.

import XCTest
@testable import SaQura

/// Defense-in-Depth parity with .NET 1.0.7 (commit `d849b6e`).
///
/// Two layers under test:
///  1. **Pre-flight input validation** at the API boundary —
///     `CallerInputValidator.ensurePublicKey / ensurePrivateKey /
///     ensureSecret` reject empty + all-zero buffers BEFORE any backend
///     work. The all-zero check catches the `(nil, nil)` failure mode
///     reported by Tresor when their tool passed back a zero-wiped key.
///  2. **Output sanity-net** wraps any internal helper regression that
///     returns an empty tuple instead of throwing the v1.0.6 typed
///     error.
///
/// Both layers also surface through the `Quantum.encrypt` /
/// `Quantum.decrypt` / `Quantum.generateKeyPair` entry points (tested
/// here as integration assertions) so the sanity-net catches regressions
/// in either the call site or the helper.
final class QuantumDefenseInDepthTests: XCTestCase {

    // MARK: - CallerInputValidator: ensurePublicKey

    func testEnsurePublicKeyAcceptsRealKey() throws {
        // 22 KB FrodoKEM-class buffer; first byte non-zero means the
        // all-zero scan exits in O(1).
        var key = Data(count: 22 * 1024)
        key[0] = 0x42
        XCTAssertNoThrow(try CallerInputValidator.ensurePublicKey(key))
    }

    func testEnsurePublicKeyRejectsEmpty() {
        XCTAssertThrowsError(try CallerInputValidator.ensurePublicKey(Data())) { error in
            guard case let SaQuraError.invalidInput(message) = error else {
                XCTFail("Expected SaQuraError.invalidInput, got \(error)")
                return
            }
            XCTAssertTrue(message.contains("cannot be empty"), "Got: \(message)")
        }
    }

    func testEnsurePublicKeyRejectsAllZero() {
        let zeroes = Data(count: 1024)
        XCTAssertThrowsError(try CallerInputValidator.ensurePublicKey(zeroes)) { error in
            guard case let SaQuraError.invalidInput(message) = error else {
                XCTFail("Expected SaQuraError.invalidInput, got \(error)")
                return
            }
            XCTAssertTrue(message.contains("all-zero"), "Got: \(message)")
            XCTAssertTrue(message.contains("zero-wiped"), "Got: \(message)")
        }
    }

    // MARK: - CallerInputValidator: ensurePrivateKey

    func testEnsurePrivateKeyRejectsEmptyAndAllZero() {
        XCTAssertThrowsError(try CallerInputValidator.ensurePrivateKey(Data()))
        XCTAssertThrowsError(try CallerInputValidator.ensurePrivateKey(Data(count: 100)))
    }

    func testEnsurePrivateKeyAcceptsRealKey() throws {
        var sk = Data(count: 16)
        sk[5] = 0x01
        XCTAssertNoThrow(try CallerInputValidator.ensurePrivateKey(sk))
    }

    // MARK: - CallerInputValidator: ensureSecret

    func testEnsureSecretRejectsEmptyAndAllZero() {
        XCTAssertThrowsError(try CallerInputValidator.ensureSecret(Data()))
        XCTAssertThrowsError(try CallerInputValidator.ensureSecret(Data(count: 32))) { error in
            guard case let SaQuraError.invalidInput(message) = error else {
                XCTFail("Expected SaQuraError.invalidInput, got \(error)")
                return
            }
            XCTAssertTrue(message.contains("secret"), "Got: \(message)")
        }
    }

    func testEnsureSecretAcceptsRealSharedSecret() throws {
        var secret = Data(count: 32)
        for i in 0..<secret.count { secret[i] = UInt8(truncatingIfNeeded: i + 1) }
        XCTAssertNoThrow(try CallerInputValidator.ensureSecret(secret))
    }

    // MARK: - Output sanity-nets

    func testEnsureEncryptOutputWrapsNilAndEmpty() {
        let gen = QuantumGeneration.gen4
        let str = QuantumStrength.highest

        XCTAssertThrowsError(
            try CallerInputValidator.ensureEncryptOutput(nil, memberName: "encryptedMessage",
                                                         generation: gen, strength: str)
        ) { error in
            guard case let QuantumOperationError.encryption(g, s, _) = error else {
                XCTFail("Expected QuantumOperationError.encryption, got \(error)")
                return
            }
            XCTAssertEqual(g, gen)
            XCTAssertEqual(s, str)
        }

        XCTAssertThrowsError(
            try CallerInputValidator.ensureEncryptOutput(Data(), memberName: "encryptedMessage",
                                                         generation: gen, strength: str)
        )
    }

    func testEnsureEncryptOutputAcceptsNonEmpty() throws {
        XCTAssertNoThrow(
            try CallerInputValidator.ensureEncryptOutput(Data([0x01]),
                                                        memberName: "encryptedMessage",
                                                        generation: .gen4, strength: .standard)
        )
    }

    func testEnsureDecryptOutputWrapsNilButAllowsEmptyString() throws {
        let gen = QuantumGeneration.gen6
        let str = QuantumStrength.medium

        XCTAssertThrowsError(
            try CallerInputValidator.ensureDecryptOutput(nil, generation: gen, strength: str)
        ) { error in
            guard case let QuantumOperationError.decryption(g, s, _) = error else {
                XCTFail("Expected QuantumOperationError.decryption, got \(error)")
                return
            }
            XCTAssertEqual(g, gen)
            XCTAssertEqual(s, str)
        }

        // Empty string is the canonical authentication-failure signal
        // — must NOT throw (mirrors .NET).
        XCTAssertNoThrow(
            try CallerInputValidator.ensureDecryptOutput("", generation: gen, strength: str)
        )
        XCTAssertNoThrow(
            try CallerInputValidator.ensureDecryptOutput("hello", generation: gen, strength: str)
        )
    }

    func testEnsureKeyGenOutputRejectsEmptyComponents() {
        let gen = QuantumGeneration.gen5
        let str = QuantumStrength.highest

        XCTAssertThrowsError(
            try CallerInputValidator.ensureKeyGenOutput(
                (publicKey: Data(), privateKey: Data([0x01])),
                generation: gen, strength: str
            )
        ) { error in
            guard case QuantumOperationError.keyGeneration = error else {
                XCTFail("Expected QuantumOperationError.keyGeneration, got \(error)")
                return
            }
        }

        XCTAssertThrowsError(
            try CallerInputValidator.ensureKeyGenOutput(
                (publicKey: Data([0x01]), privateKey: Data()),
                generation: gen, strength: str
            )
        )
    }

    func testEnsureKeyGenOutputAcceptsFullKeypair() throws {
        XCTAssertNoThrow(
            try CallerInputValidator.ensureKeyGenOutput(
                (publicKey: Data([0x01]), privateKey: Data([0x02])),
                generation: .gen2, strength: .standard
            )
        )
    }

    // MARK: - generationFromKeyByte / strengthFromKeyByte

    func testGenerationFromKeyByteReadsFirstByteAndFallsBack() {
        let gen4Key = Data([QuantumGeneration.gen4.rawValue, 0x00, 0x42])
        XCTAssertEqual(CallerInputValidator.generationFromKeyByte(gen4Key), .gen4)

        // Unknown raw byte → fallback (default .gen2, override available).
        let garbage = Data([99])
        XCTAssertEqual(CallerInputValidator.generationFromKeyByte(garbage), .gen2)
        XCTAssertEqual(CallerInputValidator.generationFromKeyByte(garbage, fallback: .gen5), .gen5)

        // Empty → fallback.
        XCTAssertEqual(CallerInputValidator.generationFromKeyByte(Data()), .gen2)
    }

    func testStrengthFromKeyByteReadsSecondByte() {
        let standardKey = Data([QuantumGeneration.gen4.rawValue, QuantumStrength.standard.rawValue, 0x42])
        let highestKey = Data([QuantumGeneration.gen7.rawValue, QuantumStrength.highest.rawValue, 0x42])

        XCTAssertEqual(CallerInputValidator.strengthFromKeyByte(standardKey), .standard)
        XCTAssertEqual(CallerInputValidator.strengthFromKeyByte(highestKey), .highest)

        // Short / empty → fallback .standard.
        XCTAssertEqual(CallerInputValidator.strengthFromKeyByte(Data([0x01])), .standard)
        XCTAssertEqual(CallerInputValidator.strengthFromKeyByte(Data()), .standard)
    }

    // MARK: - Integration: Quantum entry points enforce the pre-flight checks

    /// `Quantum.encrypt` must reject a zero-wiped public key BEFORE
    /// dispatching the async key-derivation work — i.e. it must throw
    /// SaQuraError.invalidInput, not a wrapped QuantumOperationError.
    func testQuantumEncryptRejectsZeroWipedPublicKey() async {
        let zeroes = Data(count: 1024)
        do {
            _ = try await Quantum.encrypt("hello", publicKey: zeroes)
            XCTFail("Expected SaQuraError.invalidInput, got success")
        } catch let SaQuraError.invalidInput(message) {
            XCTAssertTrue(message.contains("all-zero"), "Got: \(message)")
        } catch {
            XCTFail("Expected SaQuraError.invalidInput, got \(error)")
        }
    }

    func testQuantumEncryptRejectsEmptyPublicKey() async {
        do {
            _ = try await Quantum.encrypt("hello", publicKey: Data())
            XCTFail("Expected SaQuraError.invalidInput, got success")
        } catch let SaQuraError.invalidInput(message) {
            XCTAssertTrue(message.contains("empty"), "Got: \(message)")
        } catch {
            XCTFail("Expected SaQuraError.invalidInput, got \(error)")
        }
    }

    /// `Quantum.decrypt` must reject zero-wiped key + secret. Empty
    /// encrypted message stays the no-op contract (returns "") and is
    /// NOT subject to validation.
    func testQuantumDecryptRejectsZeroWipedPrivateKey() async {
        let zeroes = Data(count: 1024)
        let ciphertext = Data([0x42, 0x43])
        do {
            _ = try await Quantum.decrypt(ciphertext, privateKey: zeroes)
            XCTFail("Expected SaQuraError.invalidInput, got success")
        } catch let SaQuraError.invalidInput(message) {
            XCTAssertTrue(message.contains("all-zero"), "Got: \(message)")
        } catch {
            XCTFail("Expected SaQuraError.invalidInput, got \(error)")
        }
    }

    func testQuantumDecryptRejectsZeroWipedSecret() async {
        // Realistic-ish private key: 2 header bytes + non-zero content.
        var privateKey = Data(count: 32)
        privateKey[0] = QuantumGeneration.gen4.rawValue
        privateKey[1] = QuantumStrength.standard.rawValue
        for i in 2..<privateKey.count { privateKey[i] = UInt8(truncatingIfNeeded: i) }
        let ciphertext = Data([0x42, 0x43])
        let zeroSecret = Data(count: 32)
        do {
            _ = try await Quantum.decrypt(ciphertext, privateKey: privateKey, secret: zeroSecret)
            XCTFail("Expected SaQuraError.invalidInput, got success")
        } catch let SaQuraError.invalidInput(message) {
            XCTAssertTrue(message.contains("secret"), "Got: \(message)")
            XCTAssertTrue(message.contains("all-zero"), "Got: \(message)")
        } catch {
            XCTFail("Expected SaQuraError.invalidInput, got \(error)")
        }
    }

    func testQuantumDecryptEmptyCiphertextStillReturnsEmptyString() async throws {
        // Empty ciphertext → returns "" without consulting the key.
        // This is the unconditional no-op contract from .NET +
        // SaQuraSwift v1.0.5; Defense-in-Depth must not break it.
        let result = try await Quantum.decrypt(Data(), privateKey: Data())
        XCTAssertEqual(result, "")
    }
}
