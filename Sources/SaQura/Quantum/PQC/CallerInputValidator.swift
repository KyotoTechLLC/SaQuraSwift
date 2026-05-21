// CallerInputValidator.swift
// SaQura Swift Library
// Copyright (c) 2025-2026 KyotoTech LLC. All rights reserved.

import Foundation

/// Pre-flight validation for Quantum-API inputs and a sanity-net for
/// outputs. Catches caller bugs (empty / accidentally zero-wiped key
/// material) at the API boundary so consumers don't have to debug
/// silent "(nil, nil)" tuples downstream.
///
/// Swift port of the .NET 1.0.7 `CallerInputValidator` (commit
/// `d849b6e`). Same all-zero heuristic, same output sanity-net rationale:
///
///  - **All-zero detection**: a real FrodoKEM-22KB or McEliece-1MB public
///    key being all-zero is astronomically improbable (~2^-176000 odds);
///    an all-zero input is a reliable bug signal that the caller cleared
///    a cached buffer in a defense-in-depth wipe and is now passing the
///    zeroed bytes back. Short-circuits on first non-zero byte, so genuine
///    keys exit in O(1).
///  - **Output sanity-net**: guards against future regressions in the
///    cryptographic backend (CryptoKit drift, transitive-dependency
///    behaviour change, OQS upgrade). Wraps the contract violation in
///    the typed [QuantumOperationError] family so callers catching the
///    typed exception still see it.
///
/// Swift `Data` is non-nullable, so the .NET `ArgumentNullException`
/// path doesn't translate one-to-one — empty `Data` is the closest
/// analogue and gets the same diagnostic message.
internal enum CallerInputValidator {

    static func ensurePublicKey(_ publicKey: Data, paramName: String = "publicKey") throws {
        if publicKey.isEmpty {
            throw SaQuraError.invalidInput(
                "Public key cannot be empty. (parameter: \(paramName))"
            )
        }
        if isAllZero(publicKey) {
            throw SaQuraError.invalidInput(
                "Public key is all-zero — caller likely zero-wiped the buffer after a " +
                "previous operation and is now passing the cleared array back. Reload " +
                "the key from your key store or pass a fresh copy. (parameter: \(paramName))"
            )
        }
    }

    static func ensurePrivateKey(_ privateKey: Data, paramName: String = "privateKey") throws {
        if privateKey.isEmpty {
            throw SaQuraError.invalidInput(
                "Private key cannot be empty. (parameter: \(paramName))"
            )
        }
        if isAllZero(privateKey) {
            throw SaQuraError.invalidInput(
                "Private key is all-zero — caller likely zero-wiped the buffer after a " +
                "previous operation and is now passing the cleared array back. Reload " +
                "the key from your key store or pass a fresh copy. (parameter: \(paramName))"
            )
        }
    }

    static func ensureSecret(_ secret: Data, paramName: String = "secret") throws {
        if secret.isEmpty {
            throw SaQuraError.invalidInput(
                "Encapsulated secret cannot be empty. (parameter: \(paramName))"
            )
        }
        if isAllZero(secret) {
            throw SaQuraError.invalidInput(
                "Encapsulated secret is all-zero — caller likely zero-wiped the buffer " +
                "after a previous decryption. Decrypt against the original (encapsulated, " +
                "encrypted) pair from Quantum.encrypt. (parameter: \(paramName))"
            )
        }
    }

    /// Output sanity-net for Quantum encryption. Wraps any contract
    /// violation in `QuantumOperationError.encryption(...)`.
    static func ensureEncryptOutput(
        _ value: Data?,
        memberName: String,
        generation: QuantumGeneration,
        strength: QuantumStrength
    ) throws {
        if value == nil || value!.isEmpty {
            throw QuantumOperationError.encryption(
                generation: generation,
                strength: strength,
                underlyingError: SaQuraError.invalidInput(
                    "Internal Quantum helper returned a nil or empty \(memberName). " +
                    "This indicates a regression in the cryptographic backend " +
                    "(CryptoKit drift, OQS binding, or an unexpected public-key encoding). " +
                    "Please file an issue with the call site."
                )
            )
        }
    }

    /// Output sanity-net for Quantum decryption.
    ///
    /// Mirrors .NET semantics: `nil` is treated as an internal regression
    /// (the helper should return an *empty string* on authentication
    /// failure, not `nil`). Swift's contract is identical.
    static func ensureDecryptOutput(
        _ value: String?,
        generation: QuantumGeneration,
        strength: QuantumStrength
    ) throws {
        if value == nil {
            throw QuantumOperationError.decryption(
                generation: generation,
                strength: strength,
                underlyingError: SaQuraError.invalidInput(
                    "Internal Quantum helper returned a nil plaintext where an empty " +
                    "string was expected for authentication failure. This indicates a " +
                    "backend regression."
                )
            )
        }
    }

    static func ensureKeyGenOutput(
        _ keyPair: (publicKey: Data, privateKey: Data),
        generation: QuantumGeneration,
        strength: QuantumStrength
    ) throws {
        if keyPair.publicKey.isEmpty {
            throw QuantumOperationError.keyGeneration(
                generation: generation,
                strength: strength,
                underlyingError: SaQuraError.invalidInput(
                    "Internal Quantum helper returned an empty public key. This " +
                    "indicates a regression in the cryptographic backend."
                )
            )
        }
        if keyPair.privateKey.isEmpty {
            throw QuantumOperationError.keyGeneration(
                generation: generation,
                strength: strength,
                underlyingError: SaQuraError.invalidInput(
                    "Internal Quantum helper returned an empty private key. This " +
                    "indicates a regression in the cryptographic backend."
                )
            )
        }
    }

    /// Derives a `QuantumGeneration` from the first byte of a key buffer
    /// if it encodes one; otherwise falls back to the supplied default.
    /// Used for diagnostic decoration on the typed exceptions when the
    /// caller didn't pass a generation explicitly.
    static func generationFromKeyByte(
        _ key: Data,
        fallback: QuantumGeneration = .gen2
    ) -> QuantumGeneration {
        guard !key.isEmpty else { return fallback }
        return QuantumGeneration(rawValue: key[key.startIndex]) ?? fallback
    }

    /// Derives a `QuantumStrength` from the second byte of a key buffer
    /// if it encodes one; otherwise falls back to `.standard`.
    static func strengthFromKeyByte(_ key: Data) -> QuantumStrength {
        guard key.count >= 2 else { return .standard }
        return QuantumStrength(rawValue: key[key.startIndex + 1]) ?? .standard
    }

    /// Constant-time-ish all-zero check with short-circuit on first
    /// non-zero byte. Real keys exit in O(1); only the bug case pays the
    /// O(n) scan.
    private static func isAllZero(_ buffer: Data) -> Bool {
        for byte in buffer {
            if byte != 0 { return false }
        }
        return true
    }
}
