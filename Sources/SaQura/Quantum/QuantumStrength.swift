// QuantumStrength.swift
// SaQura Swift Library
// Copyright (c) 2025-2026 KyotoTech LLC. All rights reserved.

import Foundation

/// Security levels for post-quantum key generation
/// Matches .NET SaQura QuantumStrength enum (Standard=0, Medium=1, Highest=2)
public enum QuantumStrength: UInt8, Codable, CaseIterable, Sendable {
    /// Standard security (128-bit) — FrodoKEM-640 / CMCE-6688128
    case standard = 0

    /// Medium security (192-bit) — FrodoKEM-976 / CMCE-6960119
    case medium = 1

    /// Highest security (256-bit) — FrodoKEM-1344 / CMCE-8192128
    case highest = 2

    /// Display name for the strength level
    public var displayName: String {
        switch self {
        case .standard: return "Standard"
        case .medium: return "Medium"
        case .highest: return "Highest"
        }
    }

    /// Security level in bits
    public var securityBits: Int {
        switch self {
        case .standard: return 128
        case .medium: return 192
        case .highest: return 256
        }
    }
}
