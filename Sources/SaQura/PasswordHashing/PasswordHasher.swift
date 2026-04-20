// PasswordHasher.swift
// SaQura Swift Library
// Copyright (c) 2025-2026 KyotoTech LLC. All rights reserved.

import Foundation
import CommonCrypto

/// Secure password hashing using PBKDF2-SHA512
/// Output format: JSON (compatible with .NET SaQura)
public struct PasswordHasher {
    // Default parameters (OWASP 2025 recommendations)
    public static let defaultIterations = 210_000
    public static let defaultSaltLength = 32
    public static let defaultOutputLength = 64

    // Minimum requirements for migration
    private static let minimumIterations = 100_000
    private static let iterationUpgradeThreshold = 210_000

    // MARK: - Hash Generation

    /// Hashes a password with secure defaults
    /// - Parameter password: The password to hash
    /// - Returns: JSON string containing hash and parameters
    public static func hash(_ password: String) throws -> String {
        return try hash(password, iterations: defaultIterations)
    }

    /// Hashes a password with custom iteration count
    /// - Parameters:
    ///   - password: The password to hash
    ///   - iterations: Number of PBKDF2 iterations
    /// - Returns: JSON string containing hash and parameters
    public static func hash(_ password: String, iterations: Int = defaultIterations) throws -> String {
        guard !password.isEmpty else {
            throw SaQuraError.invalidInput("Password cannot be empty")
        }

        let salt = Data.secureRandom(count: defaultSaltLength)

        guard let derivedKey = CryptoUtils.deriveKey(
            password: password,
            salt: salt,
            iterations: iterations,
            keyLength: defaultOutputLength
        ) else {
            throw SaQuraError.hashingFailed("PBKDF2 key derivation failed")
        }

        let model = PasswordHashModel(
            algorithm: "pbkdf2",
            version: 2,
            salt: salt.toBase64(),
            hash: derivedKey.toBase64(),
            parameters: AlgorithmParameters(
                hashAlgorithm: "SHA512",
                iterations: iterations,
                outputLength: defaultOutputLength,
                saltLength: defaultSaltLength
            ),
            createdUtc: Date()
        )

        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys]

        let jsonData = try encoder.encode(model)
        guard var jsonString = String(data: jsonData, encoding: .utf8) else {
            throw SaQuraError.hashingFailed("Failed to encode hash to JSON")
        }

        // Apply watermark for unlicensed
        if !isDebugMode && !ApiLicense.isPasswordHashingAvailable {
            jsonString = WatermarkHelper.applyWatermarkToBase64(jsonString, context: "HASH")
        }

        return jsonString
    }

    // MARK: - Verification

    /// Verifies a password against a stored hash
    /// - Parameters:
    ///   - password: The password to verify
    ///   - hashJson: The stored hash in JSON format
    /// - Returns: True if the password matches
    public static func verify(_ password: String, hash hashJson: String) throws -> Bool {
        guard !password.isEmpty else { return false }

        // Remove watermark if present
        var actualHash = hashJson
        if WatermarkHelper.hasWatermark(hashJson) {
            actualHash = WatermarkHelper.removeWatermarkFromBase64(hashJson)
        }

        guard let jsonData = actualHash.data(using: .utf8) else {
            return false
        }

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601

        let model: PasswordHashModel
        do {
            model = try decoder.decode(PasswordHashModel.self, from: jsonData)
        } catch {
            return false
        }

        guard let salt = Data(base64Encoded: model.salt),
              let storedHash = Data(base64Encoded: model.hash) else {
            return false
        }

        guard let derivedKey = CryptoUtils.deriveKey(
            password: password,
            salt: salt,
            iterations: model.parameters.iterations,
            keyLength: model.parameters.outputLength
        ) else {
            return false
        }

        return derivedKey.secureCompare(storedHash)
    }

    // MARK: - Migration

    /// Checks if a hash needs to be rehashed (iterations too low)
    /// - Parameter hashJson: The stored hash in JSON format
    /// - Returns: True if rehashing is recommended
    public static func needsRehash(_ hashJson: String) -> Bool {
        var actualHash = hashJson
        if WatermarkHelper.hasWatermark(hashJson) {
            actualHash = WatermarkHelper.removeWatermarkFromBase64(hashJson)
        }

        guard let jsonData = actualHash.data(using: .utf8) else {
            return true
        }

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601

        guard let model = try? decoder.decode(PasswordHashModel.self, from: jsonData) else {
            return true
        }

        // Needs rehash if iterations are below current recommendation
        return model.parameters.iterations < iterationUpgradeThreshold
    }

    /// Migrates a hash if the password is verified successfully and rehashing is needed
    /// - Parameters:
    ///   - password: The password to verify and rehash
    ///   - oldHash: The old hash to verify against
    /// - Returns: New hash if migration was needed and password was correct, nil otherwise
    public static func migrateIfNeeded(_ password: String, oldHash: String) throws -> String? {
        guard try verify(password, hash: oldHash) else {
            return nil
        }

        if needsRehash(oldHash) {
            return try hash(password)
        }

        return nil
    }

    // MARK: - Password Strength

    /// Analyzes password strength
    /// - Parameter password: The password to analyze
    /// - Returns: Strength assessment result
    public static func getStrength(_ password: String) -> PasswordStrengthResult {
        var score = 0
        var suggestions: [String] = []

        let length = password.count
        let hasLowercase = password.range(of: "[a-z]", options: .regularExpression) != nil
        let hasUppercase = password.range(of: "[A-Z]", options: .regularExpression) != nil
        let hasDigits = password.range(of: "[0-9]", options: .regularExpression) != nil
        let hasSpecial = password.range(of: "[^a-zA-Z0-9]", options: .regularExpression) != nil
        let hasRepeating = password.range(of: "(.)\\1{2,}", options: .regularExpression) != nil
        let hasSequential = containsSequentialChars(password)

        // Length scoring
        if length < 8 {
            suggestions.append("Use at least 8 characters")
        } else if length < 12 {
            score += 20
        } else if length < 16 {
            score += 30
        } else {
            score += 40
        }

        // Complexity scoring
        if hasLowercase { score += 10 } else { suggestions.append("Add lowercase letters") }
        if hasUppercase { score += 10 } else { suggestions.append("Add uppercase letters") }
        if hasDigits { score += 10 } else { suggestions.append("Add numbers") }
        if hasSpecial { score += 15 } else { suggestions.append("Add special characters") }

        // Bonus for long passwords
        if length >= 20 { score += 10 }
        if length >= 30 { score += 5 }

        // Penalties
        if hasRepeating {
            score -= 10
            suggestions.append("Avoid repeating characters")
        }
        if hasSequential {
            score -= 10
            suggestions.append("Avoid sequential characters")
        }

        // Clamp score
        score = max(0, min(100, score))

        // Determine level
        let level: PasswordStrengthLevel
        switch score {
        case 0..<20: level = .veryWeak
        case 20..<40: level = .weak
        case 40..<60: level = .fair
        case 60..<80: level = .strong
        default: level = .veryStrong
        }

        return PasswordStrengthResult(
            score: score,
            level: level,
            description: level.description,
            suggestions: suggestions
        )
    }

    /// Checks for sequential characters (abc, 123, etc.)
    private static func containsSequentialChars(_ password: String) -> Bool {
        let chars = Array(password.lowercased())
        guard chars.count >= 3 else { return false }

        for i in 0..<(chars.count - 2) {
            if let a = chars[i].asciiValue,
               let b = chars[i+1].asciiValue,
               let c = chars[i+2].asciiValue {
                if (b == a + 1 && c == a + 2) || (b == a - 1 && c == a - 2) {
                    return true
                }
            }
        }

        return false
    }
}
