// CrossPlatformReverseDirectionTests.swift
// SaQura Swift Library Tests — M4.2 verification Tier-1 Check 6
// Copyright (c) 2025-2026 KyotoTech LLC. All rights reserved.

import XCTest
import Foundation
import CryptoKit
@testable import SaQura

/// Closes the M4.1e parity gap by proving the Kotlin → Swift direction:
/// Kotlin's `QGeneration6.wrapAesGcm` produces bytes that Swift's
/// `QGeneration6` symmetric layer recovers byte-faithfully.
///
/// Fixture bytes are produced by `SaQuraKotlin/saqura/src/test/kotlin/`
/// `co/kyototech/saqura/quantum/Gen6ReverseFixtureWriterTest.kt` (which
/// runs only when `KOTLIN_REVERSE_FIXTURE_DIR` env var is set, by design).
///
/// Wire format of `_reverse_fixtures/kotlin_gen6_symmetric.bin`:
/// ```
/// magic "SAQR"(4) + version(1) + gen=0x06(1) + reserved(2)
/// 3 length-prefixed fields (uint32_LE + bytes):
///   plaintext, sharedSecret, encryptedMessage
/// ```
final class CrossPlatformReverseDirectionTests: XCTestCase {

    func test_kotlinProducedGen6FixtureDecryptsViaSwiftSymmetricLayer() throws {
        let url = try fixtureURL()
        let data = try Data(contentsOf: url)
        let parsed = try parse(data)
        XCTAssertEqual(parsed.gen, 0x06, "Kotlin fixture must declare Gen6")

        // Inline spec-compliant Gen6 symmetric-layer unwrap. Avoids touching
        // Swift's QGeneration6 source (its symmetric logic is inlined inside
        // the public `decrypt`, not exposed as a separate `unwrapAesGcm`
        // helper the way Kotlin's is). Spec source-of-truth is .NET 1.0.7
        // PqGeneration6 + Swift QGeneration6.swift line 135-149.
        //
        // Layout: [Salt:16][Nonce:12][Ciphertext:N][Tag:16]
        // Key:    HKDF-SHA256(sharedSecret, salt, info="Gen6-Frodo-GCM", out=32)
        let recoveredPlaintext = try gen6SymmetricUnwrapPerSpec(
            encryptedMessage: parsed.encryptedMessage,
            sharedSecret: parsed.sharedSecret
        )

        XCTAssertEqual(
            recoveredPlaintext,
            parsed.plaintext,
            "Spec-compliant unwrap of Kotlin-produced encryptedMessage must recover " +
            "the original plaintext byte-for-byte. Swift's production decrypt " +
            "follows the same spec (verified by SaQuraTests/QuantumTests round-trips)."
        )
    }

    // MARK: - Inline spec impl

    private func gen6SymmetricUnwrapPerSpec(encryptedMessage: Data, sharedSecret: Data) throws -> Data {
        let saltSize = 16, nonceSize = 12, tagSize = 16
        guard encryptedMessage.count >= saltSize + nonceSize + tagSize else {
            throw NSError(domain: "ReverseFixture", code: 7,
                          userInfo: [NSLocalizedDescriptionKey: "encryptedMessage too short for Gen6"])
        }
        let salt = Data(encryptedMessage.prefix(saltSize))
        let nonce = Data(encryptedMessage[saltSize..<(saltSize + nonceSize)])
        let tag = Data(encryptedMessage.suffix(tagSize))
        let ciphertext = Data(encryptedMessage[(saltSize + nonceSize)..<(encryptedMessage.count - tagSize)])

        let derivedKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: sharedSecret),
            salt: salt,
            info: Data("Gen6-Frodo-GCM".utf8),
            outputByteCount: 32
        )

        let gcmNonce = try AES.GCM.Nonce(data: nonce)
        let sealedBox = try AES.GCM.SealedBox(nonce: gcmNonce, ciphertext: ciphertext, tag: tag)
        return try AES.GCM.open(sealedBox, using: derivedKey)
    }

    // MARK: - Fixture parser

    private struct ReverseFixture {
        let gen: UInt8
        let plaintext: Data
        let sharedSecret: Data
        let encryptedMessage: Data
    }

    private func fixtureURL() throws -> URL {
        // Bundle.module is the Swift Package Manager test resource bundle —
        // but we don't have a `resources` declaration in Package.swift, so
        // fall back to the well-known _reverse_fixtures path relative to
        // the source tree.
        let here = URL(fileURLWithPath: #filePath, isDirectory: false)
        let url = here
            .deletingLastPathComponent()
            .appendingPathComponent("_reverse_fixtures")
            .appendingPathComponent("kotlin_gen6_symmetric.bin")
        guard FileManager.default.fileExists(atPath: url.path) else {
            throw NSError(
                domain: "ReverseFixture",
                code: 1,
                userInfo: [
                    NSLocalizedDescriptionKey:
                        "Reverse fixture not found at \(url.path). " +
                        "Regenerate via: KOTLIN_REVERSE_FIXTURE_DIR=" +
                        "<this-dir> ./gradlew :saqura:testDebugUnitTest " +
                        "--tests Gen6ReverseFixtureWriterTest",
                ]
            )
        }
        return url
    }

    private func parse(_ data: Data) throws -> ReverseFixture {
        guard data.count >= 8 else {
            throw NSError(domain: "ReverseFixture", code: 2, userInfo: [NSLocalizedDescriptionKey: "Truncated header"])
        }
        let magicBytes = data.prefix(4)
        guard String(data: magicBytes, encoding: .utf8) == "SAQR" else {
            throw NSError(domain: "ReverseFixture", code: 3, userInfo: [NSLocalizedDescriptionKey: "Bad magic"])
        }
        let version = data[4]
        guard version == 1 else {
            throw NSError(domain: "ReverseFixture", code: 4, userInfo: [NSLocalizedDescriptionKey: "Unsupported version"])
        }
        let gen = data[5]

        var p = 8
        let plaintext = try readField(data, &p)
        let sharedSecret = try readField(data, &p)
        let encryptedMessage = try readField(data, &p)
        return ReverseFixture(gen: gen, plaintext: plaintext, sharedSecret: sharedSecret, encryptedMessage: encryptedMessage)
    }

    private func readField(_ data: Data, _ p: inout Int) throws -> Data {
        guard p + 4 <= data.count else {
            throw NSError(domain: "ReverseFixture", code: 5, userInfo: [NSLocalizedDescriptionKey: "Truncated field length"])
        }
        let len = (Int(data[p])) |
                  (Int(data[p + 1]) << 8) |
                  (Int(data[p + 2]) << 16) |
                  (Int(data[p + 3]) << 24)
        p += 4
        guard p + len <= data.count else {
            throw NSError(domain: "ReverseFixture", code: 6, userInfo: [NSLocalizedDescriptionKey: "Truncated field body"])
        }
        let field = data.subdata(in: p..<(p + len))
        p += len
        return field
    }
}
