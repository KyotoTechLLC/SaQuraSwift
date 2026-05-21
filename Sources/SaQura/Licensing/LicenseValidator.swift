// LicenseValidator.swift
// SaQura Swift Library
// Copyright (c) 2025-2026 KyotoTech LLC. All rights reserved.

import Foundation
import Security
import CryptoKit

/// Validates licenses using RSA signature verification
/// Compatible with .NET SaQura license format
internal enum LicenseValidator {
    // Embedded public key for signature verification (RSA 4096)
    // Same key as .NET SaQura - updated 2024-12-31
    private static let publicKeyPEM = """
    -----BEGIN RSA PUBLIC KEY-----
    MIICCgKCAgEApkBzQEjao0o6lnYLoXtqhLUSqVlxodMJ1wPAVznSMsCPC3KQR6gF
    DE4FJXRPup0TKbZCheHqYFsigxDEoZsgOA1v9rxnJCzEkxrLv5SH/4P1UDJM435J
    jBhe+flT3gZOqiAQcH+fCs0pfdRlVdgRjR6cVP3qYvyQGuZbSsqcDfXUpyuAs7jd
    WFLjNcyngNdkPWg50d+Sm8DcG+jnsSU1TLbsswKZolvbZIqmQnW54/OhPNSkrM7a
    YPiupOnUKxi8AfvJmHf6MILc5ykby1ldcozaJVggqE3zhh6rcAFdXK88gqGFFx81
    F1F8OjKdt8h4UnqjX+BEBZnEae231rj7S1BRvomcp0cNLuAWQXRLl3V1LXkkfkUW
    kgMp17uWz69FqHCxOV2q85sjVa8p0R5PbTzeZBxIWsQZc9f5y6IuSVB90y5EvS+9
    tlO7IL5MPIRz9Wfcn8S8PXv1R71v43RJiY7kcS3mKtRAzkYTPqF9aI8qp6L9W5BP
    SnfiWK2xABFWb2GZGZ2gJlbK7yWP1QOghToUL21iEzO1zcow43YU0HXTGqzztUtL
    F2I4F7msbOVGtRIggUSxoTuVHWrXevaePet0mp6mMzjehtxf+llbV5dp9W82c/1c
    Rcub1A5z+VEPmT6QLuLcfSQBVuNoTlqoCdfwYhEOI5vRL4NEDyEYG90CAwEAAQ==
    -----END RSA PUBLIC KEY-----
    """

    // MARK: - Validation

    /// Validates a license completely (signature, expiry, hardware, etc.)
    static func validateLicense(_ license: LicenseInfo, checkHardware: Bool = true) -> ValidationResult {
        // Check if license is internal (bypass all validation)
        if license.tier == .internal {
            return ValidationResult(
                isValid: true,
                features: .all,
                tier: .internal,
                daysRemaining: Int.max
            )
        }

        // Check signature (required for all license types)
        guard verifySignature(license) else {
            return ValidationResult(
                isValid: false,
                errorMessage: "Invalid license signature"
            )
        }

        // Check revocation
        if license.isRevoked {
            return ValidationResult(
                isValid: false,
                errorMessage: "License has been revoked"
            )
        }

        // Check dates
        let now = Date()
        if now < license.issuedAt {
            return ValidationResult(
                isValid: false,
                errorMessage: "License not yet valid"
            )
        }

        if now > license.expiresAt {
            return ValidationResult(
                isValid: false,
                errorMessage: "License expired on \(ISO8601DateFormatter().string(from: license.expiresAt))",
                isExpired: true
            )
        }

        // Distribution licenses skip hardware binding and activation count checks
        if license.type == .distribution {
            let daysRemaining = Calendar.current.dateComponents([.day], from: now, to: license.expiresAt).day ?? 0
            var warning: String? = nil
            if daysRemaining <= 30 {
                warning = "Distribution license expires in \(daysRemaining) days"
            }

            return ValidationResult(
                isValid: true,
                warning: warning,
                features: license.features,
                tier: license.tier,
                daysRemaining: daysRemaining,
                isDistributionLicense: true
            )
        }

        // Standard licenses: Check hardware binding
        // Skip hardware check on mobile platforms (iOS) as hardware IDs are not stable
        if checkHardware, let boundHardwareId = license.hardwareId, !boundHardwareId.isEmpty {
            if !HardwareIdGenerator.isMobilePlatform {
                let currentHardwareId = HardwareIdGenerator.getHardwareId()
                if !constantTimeCompare(boundHardwareId, currentHardwareId) {
                    return ValidationResult(
                        isValid: false,
                        errorMessage: "License is bound to different hardware",
                        hardwareMismatch: true
                    )
                }
            }
        }

        // Check activation count (distribution licenses have maxActivations = -1)
        if license.maxActivations >= 0 && license.currentActivations > license.maxActivations {
            return ValidationResult(
                isValid: false,
                errorMessage: "Maximum activations exceeded (\(license.currentActivations)/\(license.maxActivations))"
            )
        }

        // All checks passed
        let daysRemaining = Calendar.current.dateComponents([.day], from: now, to: license.expiresAt).day ?? 0
        var warning: String? = nil
        if daysRemaining <= 30 {
            warning = "License expires in \(daysRemaining) days"
        }

        return ValidationResult(
            isValid: true,
            warning: warning,
            features: license.features,
            tier: license.tier,
            daysRemaining: daysRemaining
        )
    }

    // MARK: - Signature Verification

    /// Verifies the RSA signature of a license
    private static func verifySignature(_ license: LicenseInfo) -> Bool {
        guard !license.signature.isEmpty else { return false }

        // Create signing data (must match server-side)
        let signingData = createSigningData(license)
        guard let dataBytes = signingData.data(using: .utf8),
              let signatureBytes = Data(base64Encoded: license.signature) else {
            return false
        }

        // Import public key
        guard let publicKey = importPublicKey() else {
            InternalLogger.log("Failed to import public key", level: .error)
            return false
        }

        // Verify signature using PKCS1-SHA256 (matches .NET)
        var error: Unmanaged<CFError>?
        let result = SecKeyVerifySignature(
            publicKey,
            .rsaSignatureMessagePKCS1v15SHA256,
            dataBytes as CFData,
            signatureBytes as CFData,
            &error
        )

        if let error = error {
            InternalLogger.log("Signature verification failed: \(error.takeRetainedValue())", level: .error)
        }

        return result
    }

    /// Creates the data to be signed (must match server-side exactly).
    ///
    /// **Bug history (2026-05-12 fix).** Until today this method called
    /// `.uppercased()` on every UUID. The .NET license server signs with
    /// `Guid.ToString()`, which emits **lowercase** UUIDs by default, so
    /// the Swift-side signing string never matched what the server signed
    /// — every real `.lic` failed verification. The bug was undetected
    /// because the Swift library had no License-system tests prior to
    /// the test sweep on 2026-05-12 (see `LicenseValidatorTests`). The
    /// fix here aligns Swift with .NET by using `.lowercased()`. A more
    /// defensive long-term solution (also done by Kotlin M3) would
    /// preserve the raw JSON string verbatim — that change is deferred
    /// to a future revision so callers building licenses programmatically
    /// (e.g. INTERNAL test fixtures) don't have to track the raw bytes.
    private static func createSigningData(_ license: LicenseInfo) -> String {
        var components: [String] = []

        components.append(license.id.uuidString.lowercased())
        components.append(license.licenseKey)
        components.append(license.product)
        components.append(String(license.tier.rawValue))
        components.append(String(license.features.rawValue))
        components.append(license.customer.id.uuidString.lowercased())
        components.append(license.customer.email)

        // Use raw strings if available (for signature verification accuracy)
        if let issuedAtRaw = license.issuedAtRaw {
            components.append(issuedAtRaw)
        } else {
            components.append(ISO8601DateFormatter().string(from: license.issuedAt))
        }

        if let expiresAtRaw = license.expiresAtRaw {
            components.append(expiresAtRaw)
        } else {
            components.append(ISO8601DateFormatter().string(from: license.expiresAt))
        }

        components.append(String(license.maxActivations))
        components.append(String(license.type.rawValue))

        // ParentLicenseId is included for distribution licenses
        if let parentId = license.parentLicenseId {
            components.append(parentId.uuidString.lowercased())
        }

        if let hardwareId = license.hardwareId, !hardwareId.isEmpty {
            components.append(hardwareId)
        }

        return components.joined(separator: "|")
    }

    /// Imports the public key from PEM format
    private static func importPublicKey() -> SecKey? {
        // Extract base64 content
        var pemContent = publicKeyPEM
            .replacingOccurrences(of: "-----BEGIN RSA PUBLIC KEY-----", with: "")
            .replacingOccurrences(of: "-----END RSA PUBLIC KEY-----", with: "")
            .replacingOccurrences(of: "\n", with: "")
            .trimmingCharacters(in: .whitespaces)

        guard let keyData = Data(base64Encoded: pemContent) else {
            return nil
        }

        // For RSA PUBLIC KEY format (PKCS#1), we need to wrap it in SPKI format
        // or use a different approach
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 4096
        ]

        var error: Unmanaged<CFError>?
        guard let secKey = SecKeyCreateWithData(keyData as CFData, attributes as CFDictionary, &error) else {
            // Try with additional header for SPKI format
            let spkiData = wrapPKCS1InSPKI(keyData)
            return SecKeyCreateWithData(spkiData as CFData, attributes as CFDictionary, nil)
        }

        return secKey
    }

    /// Wraps PKCS#1 RSA public key in SPKI format
    private static func wrapPKCS1InSPKI(_ pkcs1Data: Data) -> Data {
        // RSA OID: 1.2.840.113549.1.1.1
        let rsaOID: [UInt8] = [0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00]

        var spki = Data()

        // Calculate lengths
        let bitStringLength = pkcs1Data.count + 1 // +1 for unused bits byte
        let sequenceLength = rsaOID.count + encodeLength(bitStringLength).count + 1 + bitStringLength

        // Outer SEQUENCE
        spki.append(0x30) // SEQUENCE tag
        spki.append(contentsOf: encodeLength(sequenceLength))

        // Algorithm identifier
        spki.append(contentsOf: rsaOID)

        // BIT STRING containing public key
        spki.append(0x03) // BIT STRING tag
        spki.append(contentsOf: encodeLength(bitStringLength))
        spki.append(0x00) // unused bits

        // Public key data
        spki.append(pkcs1Data)

        return spki
    }

    /// Encodes ASN.1 length
    private static func encodeLength(_ length: Int) -> [UInt8] {
        if length < 128 {
            return [UInt8(length)]
        } else if length < 256 {
            return [0x81, UInt8(length)]
        } else {
            return [0x82, UInt8(length >> 8), UInt8(length & 0xFF)]
        }
    }

    // MARK: - Key Format Validation

    /// Validates a license key format
    /// Format: PREFIX-XXXX-XXXX-XXXX-CHECKSUM
    static func validateLicenseKeyFormat(_ licenseKey: String) -> Bool {
        let parts = licenseKey.split(separator: "-").map(String.init)
        guard parts.count == 5 else { return false }

        // Check prefix is 2-4 alphanumeric characters
        let prefix = parts[0]
        guard prefix.count >= 2, prefix.count <= 4,
              prefix.allSatisfy({ $0.isLetter || $0.isNumber }) else {
            return false
        }

        // Check each segment is 4 alphanumeric characters
        for i in 1..<5 {
            let segment = parts[i]
            guard segment.count == 4,
                  segment.allSatisfy({ $0.isLetter || $0.isNumber }) else {
                return false
            }
        }

        // Verify checksum
        let dataToHash = parts[0..<4].joined(separator: "-")
        let expectedChecksum = generateChecksum(dataToHash)

        return parts[4] == expectedChecksum
    }

    /// Generates a checksum for license key validation
    private static func generateChecksum(_ data: String) -> String {
        let hash = Data(data.utf8).sha256()
        let base64 = hash.base64EncodedString()
            .replacingOccurrences(of: "+", with: "")
            .replacingOccurrences(of: "/", with: "")
            .replacingOccurrences(of: "=", with: "")

        return String(base64.prefix(4)).uppercased()
    }

    /// Constant-time string comparison to prevent timing attacks
    private static func constantTimeCompare(_ a: String, _ b: String) -> Bool {
        guard a.count == b.count else { return false }

        var diff: UInt8 = 0
        for (charA, charB) in zip(a.utf8, b.utf8) {
            diff |= charA ^ charB
        }

        return diff == 0
    }

    // MARK: - Deserialization

    /// Deserializes a license from JSON and extracts raw DateTime strings
    static func deserializeLicense(_ json: String) -> LicenseInfo? {
        guard let jsonData = json.data(using: .utf8) else { return nil }

        do {
            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .custom(decodeDotNetIso8601)

            var license = try decoder.decode(LicenseInfo.self, from: jsonData)

            // Extract raw date strings for signature verification
            if let jsonObject = try JSONSerialization.jsonObject(with: jsonData) as? [String: Any] {
                if let issuedAt = jsonObject["issuedAt"] as? String {
                    license.issuedAtRaw = issuedAt
                }
                if let expiresAt = jsonObject["expiresAt"] as? String {
                    license.expiresAtRaw = expiresAt
                }
            }

            return license
        } catch {
            InternalLogger.log("Failed to deserialize license: \(error)", level: .error)
            return nil
        }
    }

    /// Custom date decoder tolerant of the formats the .NET license
    /// server actually emits.
    ///
    /// **Bug history.** Before this helper existed, `deserializeLicense`
    /// used `JSONDecoder.dateDecodingStrategy = .iso8601`, whose default
    /// `ISO8601DateFormatter` does NOT accept fractional seconds at all
    /// — and .NET's `DateTime.ToString("O")` emits **seven** fractional
    /// digits (100 ns ticks): `2025-12-31T06:51:41.7352260Z`. Every
    /// production `.lic` file therefore caused `deserializeLicense` to
    /// throw and return nil, breaking every Swift consumer trying to
    /// activate a real license. The bug went undetected because the
    /// Swift library had no License-system tests prior to the 2026-05-12
    /// test sweep (see `LicenseValidatorTests`).
    ///
    /// **Fidelity note.** Foundation's date types only retain
    /// millisecond precision; the sub-millisecond digits .NET emits are
    /// truncated here. That is safe because the signing string uses the
    /// **raw** date string from `issuedAtRaw` / `expiresAtRaw`, not the
    /// parsed `Date`, so signature verification still matches byte-for-byte.
    private static func decodeDotNetIso8601(_ decoder: Decoder) throws -> Date {
        let container = try decoder.singleValueContainer()
        let raw = try container.decode(String.self)

        // Trim sub-millisecond fractional digits down to 3 so
        // ISO8601DateFormatter with .withFractionalSeconds can handle it.
        let normalized = normalizeDotNetTimestamp(raw)

        let withFractional = ISO8601DateFormatter()
        withFractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = withFractional.date(from: normalized) {
            return date
        }
        let plain = ISO8601DateFormatter()
        plain.formatOptions = [.withInternetDateTime]
        if let date = plain.date(from: normalized) {
            return date
        }
        throw DecodingError.dataCorruptedError(
            in: container,
            debugDescription: "Unparseable ISO8601 timestamp: \(raw)"
        )
    }

    /// Truncates `.NNNNNNN` (more than 3 fractional digits) to `.NNN` so
    /// the result parses with `ISO8601DateFormatter.withFractionalSeconds`.
    /// Inputs with 0 or ≤3 fractional digits pass through unchanged.
    internal static func normalizeDotNetTimestamp(_ s: String) -> String {
        guard let dot = s.firstIndex(of: ".") else { return s }
        // Find the first non-digit character after the dot.
        var end = s.index(after: dot)
        while end < s.endIndex, s[end].isNumber {
            end = s.index(after: end)
        }
        let fractional = s[s.index(after: dot)..<end]
        if fractional.count <= 3 { return s }
        let trimmed = fractional.prefix(3)
        return String(s[s.startIndex..<dot]) + "." + trimmed + String(s[end..<s.endIndex])
    }
}
