// FrodoKEMHelper.swift
// SaQura Swift Library
// Copyright (c) 2025-2026 KyotoTech LLC. All rights reserved.

import Foundation

/// Maps QuantumStrength to FrodoKEM algorithm variants
internal struct FrodoKEMHelper {
    /// Returns the FrodoKEM algorithm for a given strength level
    /// - standard → FrodoKEM-640-AES
    /// - medium   → FrodoKEM-976-AES
    /// - highest  → FrodoKEM-1344-AES
    static func algorithm(for strength: QuantumStrength) -> OQSKem.Algorithm {
        switch strength {
        case .standard:
            return .frodokem640aes
        case .medium:
            return .frodokem976aes
        case .highest:
            return .frodokem1344aes
        }
    }

    /// Creates a configured OQSKem instance for the given strength
    static func createKem(for strength: QuantumStrength) throws -> OQSKem {
        return try OQSKem(algorithm: algorithm(for: strength))
    }
}
