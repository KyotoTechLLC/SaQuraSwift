// WatermarkHelper.swift
// SaQura Swift Library
// Copyright (c) 2025-2026 KyotoTech LLC. All rights reserved.

import Foundation

/// Helper for applying and removing watermarks on unlicensed output
/// Format matches .NET SaQura for compatibility
internal enum WatermarkHelper {
    // Watermark prefixes and suffixes (matches .NET)
    static let unlicensedAESPrefix = "[UNLICENSED-AES]"
    static let unlicensedAESSuffix = "[/UNLICENSED-AES]"
    static let unlicensedRSAPrefix = "[UNLICENSED-OUTPUT]"
    static let unlicensedRSASuffix = "[/UNLICENSED-OUTPUT]"
    static let unlicensedQuantumPrefix = "[UNLICENSED-QUANTUM]"
    static let unlicensedQuantumSuffix = "[/UNLICENSED-QUANTUM]"
    static let unlicensedHashPrefix = "[UNLICENSED-HASH]"
    static let unlicensedHashSuffix = "[/UNLICENSED-HASH]"

    // Generic watermark for Base64 data
    private static let watermarkHeader = "KYOTOTECH-UNLICENSED"
    private static let watermarkHeaderData = Data(watermarkHeader.utf8)

    // MARK: - String Watermarks

    /// Applies watermark to Base64 string
    static func applyWatermarkToBase64(_ base64: String, context: String) -> String {
        let prefix: String
        let suffix: String

        switch context.uppercased() {
        case "AES", "AES-GCM", "AES-PASSWORD":
            prefix = unlicensedAESPrefix
            suffix = unlicensedAESSuffix
        case "RSA", "RSA-SIG":
            prefix = unlicensedRSAPrefix
            suffix = unlicensedRSASuffix
        case "QUANTUM":
            prefix = unlicensedQuantumPrefix
            suffix = unlicensedQuantumSuffix
        case "HASH", "PASSWORD":
            prefix = unlicensedHashPrefix
            suffix = unlicensedHashSuffix
        default:
            prefix = "[UNLICENSED-\(context)]"
            suffix = "[/UNLICENSED-\(context)]"
        }

        return "\(prefix)\(base64)\(suffix)"
    }

    /// Removes watermark from Base64 string
    static func removeWatermarkFromBase64(_ watermarked: String) -> String {
        var result = watermarked

        // Try all known prefixes
        let prefixes = [unlicensedAESPrefix, unlicensedRSAPrefix, unlicensedQuantumPrefix, unlicensedHashPrefix]
        let suffixes = [unlicensedAESSuffix, unlicensedRSASuffix, unlicensedQuantumSuffix, unlicensedHashSuffix]

        for (prefix, suffix) in zip(prefixes, suffixes) {
            if result.hasPrefix(prefix) {
                result = String(result.dropFirst(prefix.count))
                if result.hasSuffix(suffix) {
                    result = String(result.dropLast(suffix.count))
                }
                return result
            }
        }

        // Try generic pattern [UNLICENSED-XXX]...[/UNLICENSED-XXX]
        if let prefixRange = result.range(of: "\\[UNLICENSED-[A-Z0-9-]+\\]", options: .regularExpression),
           prefixRange.lowerBound == result.startIndex {
            let prefix = String(result[prefixRange])
            result = String(result.dropFirst(prefix.count))

            // Find matching suffix
            let suffixPattern = prefix.replacingOccurrences(of: "[", with: "[/")
            if let suffixRange = result.range(of: suffixPattern, options: .backwards) {
                result = String(result[..<suffixRange.lowerBound])
            }
        }

        return result
    }

    /// Checks if string has watermark
    static func hasWatermark(_ value: String) -> Bool {
        let prefixes = [unlicensedAESPrefix, unlicensedRSAPrefix, unlicensedQuantumPrefix, unlicensedHashPrefix]
        return prefixes.contains { value.hasPrefix($0) } ||
               value.range(of: "^\\[UNLICENSED-[A-Z0-9-]+\\]", options: .regularExpression) != nil
    }

    // MARK: - Data Watermarks

    /// Applies watermark to binary data
    static func applyWatermark(_ data: Data, context: String) -> Data {
        var result = Data()
        result.append(watermarkHeaderData)
        result.append(Data([UInt8(context.count)]))
        result.append(Data(context.utf8))
        result.append(data)
        return result
    }

    /// Removes watermark from binary data
    static func removeWatermark(_ data: Data) -> Data {
        guard hasWatermark(data) else { return data }

        // Skip header
        var offset = watermarkHeaderData.count
        guard offset < data.count else { return data }

        // Read context length
        let contextLength = Int(data[offset])
        offset += 1

        // Skip context
        offset += contextLength

        guard offset < data.count else { return data }
        return data.suffix(from: offset)
    }

    /// Checks if data has watermark header
    static func hasWatermark(_ data: Data) -> Bool {
        guard data.count > watermarkHeaderData.count else { return false }
        return data.prefix(watermarkHeaderData.count) == watermarkHeaderData
    }
}
