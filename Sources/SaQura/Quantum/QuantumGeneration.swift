// QuantumGeneration.swift
// SaQura Swift Library
// Copyright (c) 2025-2026 KyotoTech LLC. All rights reserved.

import Foundation

/// Post-quantum key generation versions (matches .NET SaQura)
public enum QuantumGeneration: UInt8, Codable, CaseIterable, Sendable {
    /// Gen1: DEPRECATED - Vulnerable to padding oracle attacks
    /// Only available with Pro license for legacy decryption
    case gen1 = 1

    /// Gen2: Classic McEliece + AES-256-CBC + HMAC-SHA256 - Secure
    case gen2 = 2

    /// Gen3: DEPRECATED - XOR key-reuse vulnerability
    /// Only available with Pro license for legacy decryption
    case gen3 = 3

    /// Gen4: FrodoKEM-1344-AES + AES-256-GCM - Secure
    case gen4 = 4

    /// Gen5: Classic McEliece + AES-256-CBC + HMAC-SHA256 (salted) - Secure
    case gen5 = 5

    /// Gen6: FrodoKEM (strength-based) + HKDF + AES-256-GCM - Secure
    case gen6 = 6

    /// Gen7: Hybrid RSA-4096 + FrodoKEM - Maximum security
    /// Requires Pro license
    case gen7 = 7

    /// Display name for the generation
    public var displayName: String {
        switch self {
        case .gen1: return "Gen1 (Legacy)"
        case .gen2: return "Gen2 (CMCE+HMAC)"
        case .gen3: return "Gen3 (Legacy)"
        case .gen4: return "Gen4 (FrodoKEM+GCM)"
        case .gen5: return "Gen5 (CMCE+HMAC+Salt)"
        case .gen6: return "Gen6 (FrodoKEM+GCM)"
        case .gen7: return "Gen7 (RSA+FrodoKEM)"
        }
    }

    /// Whether this generation is secure for production use
    public var isSecure: Bool {
        switch self {
        case .gen1, .gen3:
            return false
        case .gen2, .gen4, .gen5, .gen6, .gen7:
            return true
        }
    }

    /// Security assessment string
    public var securityAssessment: String {
        switch self {
        case .gen1:
            return "VULNERABLE - Padding oracle attack possible"
        case .gen2:
            return "SECURE - Classic McEliece + AES-CBC + HMAC-SHA256"
        case .gen3:
            return "VULNERABLE - XOR key-reuse vulnerability"
        case .gen4:
            return "SECURE - FrodoKEM-1344 + AES-256-GCM"
        case .gen5:
            return "SECURE - Classic McEliece + AES-CBC + HMAC-SHA256 (salted)"
        case .gen6:
            return "SECURE - FrodoKEM + HKDF + AES-256-GCM"
        case .gen7:
            return "SECURE - Hybrid RSA-4096 + FrodoKEM (maximum security)"
        }
    }

    /// Whether this generation requires a Pro license
    public var requiresProLicense: Bool {
        switch self {
        case .gen1, .gen3, .gen7:
            return true
        default:
            return false
        }
    }

    /// Recommended replacement for deprecated generations
    public var recommendedReplacement: QuantumGeneration? {
        switch self {
        case .gen1:
            return .gen5
        case .gen3:
            return .gen6
        default:
            return nil
        }
    }

    /// Gets the recommended generation for a use case
    public static func recommended(forMobile: Bool, highestSecurity: Bool) -> QuantumGeneration {
        if highestSecurity {
            return .gen7
        }
        if forMobile {
            return .gen6
        }
        return .gen4
    }
}
