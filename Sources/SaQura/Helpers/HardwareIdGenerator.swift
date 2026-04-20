// HardwareIdGenerator.swift
// SaQura Swift Library
// Copyright (c) 2025-2026 KyotoTech LLC. All rights reserved.

import Foundation
import CryptoKit

#if os(iOS) || os(tvOS) || os(watchOS)
import UIKit
#endif

#if os(macOS)
import IOKit
#endif

/// Generates a unique hardware identifier for license binding
/// Compatible with .NET SaQura hardware ID generation
internal enum HardwareIdGenerator {
    private static var cachedId: String?
    private static let queue = DispatchQueue(label: "jp.kyototech.saqura.hardwareid")

    /// Whether running on a mobile platform (iOS/tvOS/watchOS)
    static var isMobilePlatform: Bool {
        #if os(iOS) || os(tvOS) || os(watchOS)
        return true
        #else
        return false
        #endif
    }

    /// Gets the hardware ID for this device
    /// On mobile platforms, returns "MOBILE-PLATFORM" to match .NET behavior
    static func getHardwareId() -> String {
        return queue.sync {
            if let cached = cachedId {
                return cached
            }

            let id = generateHardwareId()
            cachedId = id
            return id
        }
    }

    /// Generates the hardware ID
    private static func generateHardwareId() -> String {
        #if os(iOS) || os(tvOS) || os(watchOS)
        // On mobile, hardware IDs are not stable across reinstalls
        // Return a constant to match .NET behavior (HardwareIdGenerator.IsMobilePlatform)
        return "MOBILE-PLATFORM"
        #elseif os(macOS)
        return generateMacOSHardwareId()
        #else
        return "UNKNOWN-PLATFORM"
        #endif
    }

    #if os(macOS)
    /// Generates hardware ID for macOS
    private static func generateMacOSHardwareId() -> String {
        var components: [String] = []

        // Get serial number
        if let serial = getMacSerialNumber() {
            components.append(serial)
        }

        // Get primary MAC address
        if let mac = getPrimaryMACAddress() {
            components.append(mac)
        }

        // Get model identifier
        if let model = getMacModelIdentifier() {
            components.append(model)
        }

        // If we got no components, fall back to a UUID
        if components.isEmpty {
            // Use a persistent UUID stored in Keychain
            return getPersistentUUID()
        }

        // Hash the components
        let combined = components.joined(separator: "|")
        let hash = Data(combined.utf8).sha256()
        return hash.toHex()
    }

    /// Gets the Mac serial number
    private static func getMacSerialNumber() -> String? {
        let platformExpert = IOServiceGetMatchingService(
            kIOMainPortDefault,
            IOServiceMatching("IOPlatformExpertDevice")
        )

        guard platformExpert != 0 else { return nil }
        defer { IOObjectRelease(platformExpert) }

        guard let serialNumberAsCFString = IORegistryEntryCreateCFProperty(
            platformExpert,
            kIOPlatformSerialNumberKey as CFString,
            kCFAllocatorDefault,
            0
        )?.takeRetainedValue() as? String else {
            return nil
        }

        return serialNumberAsCFString
    }

    /// Gets the primary MAC address
    private static func getPrimaryMACAddress() -> String? {
        var iterator: io_iterator_t = 0
        defer {
            if iterator != 0 {
                IOObjectRelease(iterator)
            }
        }

        guard IOServiceGetMatchingServices(
            kIOMainPortDefault,
            IOServiceMatching("IOEthernetInterface"),
            &iterator
        ) == KERN_SUCCESS else {
            return nil
        }

        var macAddress: String? = nil
        var service = IOIteratorNext(iterator)

        while service != 0 {
            var controllerService: io_object_t = 0
            defer {
                IOObjectRelease(service)
                if controllerService != 0 {
                    IOObjectRelease(controllerService)
                }
            }

            if IORegistryEntryGetParentEntry(service, kIOServicePlane, &controllerService) == KERN_SUCCESS {
                if let data = IORegistryEntryCreateCFProperty(
                    controllerService,
                    "IOMACAddress" as CFString,
                    kCFAllocatorDefault,
                    0
                )?.takeRetainedValue() as? Data {
                    macAddress = data.map { String(format: "%02X", $0) }.joined(separator: ":")
                    break
                }
            }

            service = IOIteratorNext(iterator)
        }

        return macAddress
    }

    /// Gets the Mac model identifier
    private static func getMacModelIdentifier() -> String? {
        var size = 0
        sysctlbyname("hw.model", nil, &size, nil, 0)

        var model = [CChar](repeating: 0, count: size)
        sysctlbyname("hw.model", &model, &size, nil, 0)

        return String(cString: model)
    }

    /// Gets or creates a persistent UUID stored in Keychain
    private static func getPersistentUUID() -> String {
        let serviceName = "jp.kyototech.saqura"
        let accountName = "hardware-uuid"

        // Try to load existing
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: accountName,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]

        var result: AnyObject?
        if SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
           let data = result as? Data,
           let uuid = String(data: data, encoding: .utf8) {
            return uuid
        }

        // Generate new UUID
        let newUUID = UUID().uuidString

        // Store it
        let addQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: accountName,
            kSecValueData as String: newUUID.data(using: .utf8)!,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock
        ]
        SecItemAdd(addQuery as CFDictionary, nil)

        return newUUID
    }
    #endif
}
