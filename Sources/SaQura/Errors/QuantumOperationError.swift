// QuantumOperationError.swift
// SaQura Swift Library
// Copyright (c) 2025-2026 KyotoTech LLC. All rights reserved.

import Foundation

/// Diagnostic errors raised by post-quantum operations.
///
/// Mirrors the .NET `QuantumOperationException` hierarchy: a single error
/// type with three discriminated kinds, carrying the requested generation
/// and strength so callers can branch on context. The original failure (if
/// any) is preserved as `underlyingError`.
///
/// Public messages are intentionally terse — internal architecture details
/// are kept out of the surface. Callers wanting the underlying cause should
/// inspect `underlyingError`.
public enum QuantumOperationError: LocalizedError {
    /// Key generation failed unexpectedly.
    case keyGeneration(generation: QuantumGeneration, strength: QuantumStrength, underlyingError: Error?)

    /// Encryption failed unexpectedly.
    /// Authentication failures during decryption are NOT raised here — the
    /// per-generation decrypt path returns an empty plaintext for those.
    case encryption(generation: QuantumGeneration, strength: QuantumStrength, underlyingError: Error?)

    /// Decryption failed unexpectedly with an internal error (not a wrong key).
    case decryption(generation: QuantumGeneration, strength: QuantumStrength, underlyingError: Error?)

    /// The requested generation, regardless of which case is active.
    public var generation: QuantumGeneration {
        switch self {
        case .keyGeneration(let g, _, _), .encryption(let g, _, _), .decryption(let g, _, _):
            return g
        }
    }

    /// The requested strength.
    public var strength: QuantumStrength {
        switch self {
        case .keyGeneration(_, let s, _), .encryption(_, let s, _), .decryption(_, let s, _):
            return s
        }
    }

    /// The original error that triggered this failure, if one was caught.
    public var underlyingError: Error? {
        switch self {
        case .keyGeneration(_, _, let u), .encryption(_, _, let u), .decryption(_, _, let u):
            return u
        }
    }

    public var errorDescription: String? {
        switch self {
        case .keyGeneration: return "Quantum key generation failed."
        case .encryption:    return "Quantum encryption failed."
        case .decryption:    return "Quantum decryption failed."
        }
    }
}
