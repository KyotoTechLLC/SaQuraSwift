// QuantumConcurrencyTests.swift
// SaQura Swift Library Tests
// Copyright (c) 2025-2026 KyotoTech LLC. All rights reserved.

import XCTest
@testable import SaQura

/// Concurrency / stress tests for the Swift Quantum surface.
/// Test-sweep 2026-05-12.
///
/// Swift Quantum has the real liboqs backend wired (unlike Kotlin's M4.0
/// which is a placeholder), so we can exercise genuine parallel
/// encrypt + decrypt round-trips and verify the per-operation state
/// (key buffers, encapsulated secrets) doesn't leak between tasks.
final class QuantumConcurrencyTests: XCTestCase {

    // Force debug-mode so the round-trip + key-pair tests get
    // unwatermarked output. License-gating concurrency is verified by
    // the License test files, which toggle the override explicitly.
    override func setUp() { super.setUp(); debugModeOverride = true }
    override func tearDown() { debugModeOverride = nil; super.tearDown() }

    /// Round-trip: generate a Gen4 keypair, then run N parallel
    /// encrypt+decrypt cycles with distinct messages, asserting each
    /// task gets back its own message intact.
    func testParallelEncryptDecryptDoesNotLeakStateBetweenTasks() async throws {
        let (pubKey, privKey) = try await Quantum.generateKeyPair(strength: .standard, generation: .gen4)

        let messages = (0..<20).map { "task-\($0): the quick brown fox" }

        // TaskGroup parallelizes across the cooperative thread pool.
        try await withThrowingTaskGroup(of: (Int, String).self) { group in
            for (i, msg) in messages.enumerated() {
                group.addTask {
                    let cipher = try await Quantum.encrypt(msg, publicKey: pubKey)
                    let plaintext = try await Quantum.decrypt(
                        cipher.encryptedMessage,
                        privateKey: privKey,
                        secret: cipher.encapsulatedSecret
                    )
                    return (i, plaintext)
                }
            }

            // Collect; assert each task got back its own message.
            var seen = [Int: String]()
            for try await (i, plaintext) in group {
                seen[i] = plaintext
            }
            XCTAssertEqual(seen.count, messages.count)
            for (i, msg) in messages.enumerated() {
                XCTAssertEqual(seen[i], msg, "Task \(i) got wrong plaintext")
            }
        }
    }

    /// Defense-in-Depth checks must be thread-safe — running the input
    /// validators concurrently on different keys should never interfere.
    func testParallelCallerInputValidatorIsThreadSafe() async throws {
        let validKey = Data((0..<1024).map { _ in UInt8.random(in: 1...255) })
        let zeroKey = Data(count: 1024)

        try await withThrowingTaskGroup(of: Bool.self) { group in
            // 50 valid + 50 zero-wiped keys interleaved.
            for i in 0..<100 {
                group.addTask {
                    if i % 2 == 0 {
                        // Should pass.
                        try CallerInputValidator.ensurePublicKey(validKey)
                        return true
                    } else {
                        // Should throw.
                        do {
                            try CallerInputValidator.ensurePublicKey(zeroKey)
                            return false // Unexpected pass.
                        } catch {
                            return true // Expected throw.
                        }
                    }
                }
            }
            for try await ok in group {
                XCTAssertTrue(ok)
            }
        }
    }

    /// Two parallel keypair generations of the same generation must
    /// produce different keys (no shared randomness state across tasks).
    func testParallelKeyPairGenerationProducesIndependentKeys() async throws {
        async let kp1 = Quantum.generateKeyPair(strength: .standard, generation: .gen4)
        async let kp2 = Quantum.generateKeyPair(strength: .standard, generation: .gen4)

        let (pair1, pair2) = try await (kp1, kp2)
        // Same algorithm but two independent keypairs — public keys
        // should differ (probability of accidental collision is
        // astronomically low for FrodoKEM-1344).
        XCTAssertNotEqual(pair1.publicKey, pair2.publicKey)
        XCTAssertNotEqual(pair1.privateKey, pair2.privateKey)
    }
}
