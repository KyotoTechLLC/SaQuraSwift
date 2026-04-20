// PasswordHashModel.swift
// SaQura Swift Library
// Copyright (c) 2025-2026 KyotoTech LLC. All rights reserved.

import Foundation

/// Password hash result in JSON format (compatible with .NET SaQura)
public struct PasswordHashModel: Codable, Sendable {
    /// Algorithm used (always "pbkdf2")
    public let algorithm: String

    /// Version of the hash format
    public let version: Int

    /// Base64-encoded salt
    public let salt: String

    /// Base64-encoded hash
    public let hash: String

    /// Algorithm parameters
    public let parameters: AlgorithmParameters

    /// Creation timestamp (UTC)
    public let createdUtc: Date

    public init(
        algorithm: String = "pbkdf2",
        version: Int = 2,
        salt: String,
        hash: String,
        parameters: AlgorithmParameters,
        createdUtc: Date = Date()
    ) {
        self.algorithm = algorithm
        self.version = version
        self.salt = salt
        self.hash = hash
        self.parameters = parameters
        self.createdUtc = createdUtc
    }

    enum CodingKeys: String, CodingKey {
        case algorithm
        case version
        case salt
        case hash
        case parameters
        case createdUtc
    }
}

/// PBKDF2 algorithm parameters
public struct AlgorithmParameters: Codable, Sendable {
    /// Hash algorithm (e.g., "SHA512")
    public let hashAlgorithm: String

    /// Number of iterations
    public let iterations: Int

    /// Output key length in bytes
    public let outputLength: Int

    /// Salt length in bytes
    public let saltLength: Int

    public init(
        hashAlgorithm: String = "SHA512",
        iterations: Int = 210_000,
        outputLength: Int = 64,
        saltLength: Int = 32
    ) {
        self.hashAlgorithm = hashAlgorithm
        self.iterations = iterations
        self.outputLength = outputLength
        self.saltLength = saltLength
    }

    enum CodingKeys: String, CodingKey {
        case hashAlgorithm
        case iterations
        case outputLength
        case saltLength
    }
}

/// Password strength assessment result
public struct PasswordStrengthResult: Sendable {
    /// Strength score (0-100)
    public let score: Int

    /// Strength level (0-4)
    public let level: PasswordStrengthLevel

    /// Human-readable description
    public let description: String

    /// Suggestions for improvement
    public let suggestions: [String]
}

/// Password strength levels
public enum PasswordStrengthLevel: Int, Sendable {
    case veryWeak = 0
    case weak = 1
    case fair = 2
    case strong = 3
    case veryStrong = 4

    public var description: String {
        switch self {
        case .veryWeak: return "Very Weak"
        case .weak: return "Weak"
        case .fair: return "Fair"
        case .strong: return "Strong"
        case .veryStrong: return "Very Strong"
        }
    }
}
