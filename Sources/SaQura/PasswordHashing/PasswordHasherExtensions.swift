// PasswordHasherExtensions.swift
// SaQura Swift Library
// Copyright (c) 2025-2026 KyotoTech LLC. All rights reserved.

import Foundation

// MARK: - String Extensions for Password Hashing

public extension String {
    /// Hashes this string as a password using PBKDF2-SHA512
    /// - Returns: JSON string containing hash and parameters
    func hashPassword() async throws -> String {
        return try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    let hash = try PasswordHasher.hash(self)
                    continuation.resume(returning: hash)
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    /// Verifies this string (password) against a stored hash
    /// - Parameter hash: The stored hash in JSON format
    /// - Returns: True if the password matches
    func verifyPassword(hash: String) async throws -> Bool {
        return try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    let result = try PasswordHasher.verify(self, hash: hash)
                    continuation.resume(returning: result)
                } catch {
                    continuation.resume(returning: false)
                }
            }
        }
    }

    /// Gets the strength of this string as a password
    /// - Returns: Password strength score (0-100)
    func getPasswordStrength() -> Int {
        return PasswordHasher.getStrength(self).score
    }

    /// Gets detailed password strength analysis
    /// - Returns: Password strength result with score, level, and suggestions
    func analyzePasswordStrength() -> PasswordStrengthResult {
        return PasswordHasher.getStrength(self)
    }

    /// Checks if this hash needs to be rehashed (iterations too low)
    /// - Returns: True if rehashing is recommended
    func passwordHashNeedsRehash() -> Bool {
        return PasswordHasher.needsRehash(self)
    }

    /// Migrates this password to a new hash if the old hash needs updating
    /// - Parameter oldHash: The old hash to verify against
    /// - Returns: New hash if migration was needed and password was correct, nil otherwise
    func migratePasswordHashIfNeeded(oldHash: String) async throws -> String? {
        return try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    let result = try PasswordHasher.migrateIfNeeded(self, oldHash: oldHash)
                    continuation.resume(returning: result)
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }
}
