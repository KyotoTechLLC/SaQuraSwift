// LicenseStorage.swift
// SaQura Swift Library
// Copyright (c) 2025-2026 KyotoTech LLC. All rights reserved.

import Foundation
import Security

/// Secure storage for license data using Keychain
internal enum LicenseStorage {
    private static let serviceName = "jp.kyototech.saqura"
    private static let accountName = "license"

    // MARK: - Save License

    /// Saves license to Keychain
    static func saveLicense(_ license: LicenseInfo) async {
        do {
            let encoder = JSONEncoder()
            encoder.dateEncodingStrategy = .iso8601
            let data = try encoder.encode(license)

            // Delete existing
            let deleteQuery: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: serviceName,
                kSecAttrAccount as String: accountName
            ]
            SecItemDelete(deleteQuery as CFDictionary)

            // Add new
            let addQuery: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: serviceName,
                kSecAttrAccount as String: accountName,
                kSecValueData as String: data,
                kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock
            ]

            let status = SecItemAdd(addQuery as CFDictionary, nil)
            if status != errSecSuccess && status != errSecDuplicateItem {
                InternalLogger.log("Failed to save license to Keychain: \(status)", level: .error)
                // Fall back to UserDefaults
                saveToUserDefaults(data)
            }
        } catch {
            InternalLogger.log("Failed to encode license: \(error)", level: .error)
        }
    }

    // MARK: - Load License

    /// Loads license from Keychain
    static func loadLicense() async -> LicenseInfo? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: accountName,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        var data: Data? = nil

        if status == errSecSuccess, let resultData = result as? Data {
            data = resultData
        } else {
            // Try UserDefaults fallback
            data = loadFromUserDefaults()
        }

        guard let licenseData = data else { return nil }

        do {
            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .iso8601
            return try decoder.decode(LicenseInfo.self, from: licenseData)
        } catch {
            InternalLogger.log("Failed to decode license: \(error)", level: .error)
            return nil
        }
    }

    // MARK: - Clear License

    /// Clears license from storage
    static func clearLicense() async {
        // Delete from Keychain
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: accountName
        ]
        SecItemDelete(query as CFDictionary)

        // Clear UserDefaults fallback
        UserDefaults.standard.removeObject(forKey: "\(serviceName).license")
    }

    // MARK: - UserDefaults Fallback

    private static func saveToUserDefaults(_ data: Data) {
        UserDefaults.standard.set(data, forKey: "\(serviceName).license")
    }

    private static func loadFromUserDefaults() -> Data? {
        return UserDefaults.standard.data(forKey: "\(serviceName).license")
    }
}
