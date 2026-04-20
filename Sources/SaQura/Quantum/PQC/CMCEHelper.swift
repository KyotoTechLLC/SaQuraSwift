// CMCEHelper.swift
// SaQura Swift Library
// Copyright (c) 2025-2026 KyotoTech LLC. All rights reserved.

import Foundation

/// Maps QuantumStrength to Classic McEliece algorithm variants
internal struct CMCEHelper {
    /// Returns the Classic McEliece algorithm for a given strength level
    /// - standard → Classic-McEliece-6688128
    /// - medium   → Classic-McEliece-6960119
    /// - highest  → Classic-McEliece-8192128
    static func algorithm(for strength: QuantumStrength) -> OQSKem.Algorithm {
        switch strength {
        case .standard:
            return .classicMcEliece6688128
        case .medium:
            return .classicMcEliece6960119
        case .highest:
            return .classicMcEliece8192128
        }
    }

    /// Creates a configured OQSKem instance for the given strength
    static func createKem(for strength: QuantumStrength) throws -> OQSKem {
        return try OQSKem(algorithm: algorithm(for: strength))
    }
}
