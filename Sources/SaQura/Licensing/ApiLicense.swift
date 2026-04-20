// ApiLicense.swift
// SaQura Swift Library
// Copyright (c) 2025-2026 KyotoTech LLC. All rights reserved.

import Foundation

/// Public API for SaQura licensing
public enum ApiLicense {
    // MARK: - Private State

    private static var _currentLicense: LicenseInfo?
    private static var _isLicensed: Bool = false
    private static let queue = DispatchQueue(label: "jp.kyototech.saqura.license", attributes: .concurrent)

    // MARK: - Public Properties

    /// Gets whether a valid license is active
    public static var isLicensed: Bool {
        queue.sync { _isLicensed }
    }

    /// Gets the current license tier
    public static var currentTier: LicenseTier {
        queue.sync { _currentLicense?.tier ?? .free }
    }

    /// Gets the current license (if any)
    public static var currentLicense: LicenseInfo? {
        queue.sync { _currentLicense }
    }

    /// Gets whether RSA features are available (Basic+)
    public static var isRSAAvailable: Bool {
        isLicensed && currentLicense?.features.contains(.rsa) == true
    }

    /// Gets whether password hashing is available without watermark (Basic+)
    public static var isPasswordHashingAvailable: Bool {
        isLicensed && currentLicense?.features.contains(.passwordHashing) == true
    }

    /// Gets whether AES features are available (Standard+)
    public static var isAESAvailable: Bool {
        isLicensed && currentLicense?.features.contains(.aes) == true
    }

    /// Gets whether Quantum features are available (Pro+)
    public static var isQuantumAvailable: Bool {
        isLicensed && currentLicense?.features.contains(.quantum) == true
    }

    /// Gets whether output should be watermarked
    public static var requiresWatermark: Bool {
        !isLicensed || currentLicense?.features.contains(.noWatermark) != true
    }

    // MARK: - Activation Methods

    /// Activates a license key
    /// - Parameter licenseKey: The license key to activate
    /// - Returns: Activation result with success status and message
    public static func activateLicense(_ licenseKey: String) async -> ActivationResult {
        guard !licenseKey.trimmingCharacters(in: .whitespaces).isEmpty else {
            return ActivationResult(
                success: false,
                errorMessage: "License key cannot be empty"
            )
        }

        // Validate key format
        guard LicenseValidator.validateLicenseKeyFormat(licenseKey) else {
            return ActivationResult(
                success: false,
                errorMessage: "Invalid license key format"
            )
        }

        // TODO: Call licensing server for activation
        // For now, return error as we need server interaction
        return ActivationResult(
            success: false,
            errorMessage: "Online license activation requires server connection. Use activateLicenseFile() or activateLicenseFromJson() for offline activation."
        )
    }

    /// Activates a license from a signed license file (offline activation)
    /// - Parameter licenseFilePath: Path to the .lic file
    /// - Returns: Activation result with success status and message
    public static func activateLicenseFile(_ licenseFilePath: String) async -> ActivationResult {
        guard !licenseFilePath.isEmpty else {
            return ActivationResult(
                success: false,
                errorMessage: "License file path cannot be empty"
            )
        }

        guard FileManager.default.fileExists(atPath: licenseFilePath) else {
            return ActivationResult(
                success: false,
                errorMessage: "License file not found"
            )
        }

        do {
            let licenseJson = try String(contentsOfFile: licenseFilePath, encoding: .utf8)
            return await activateLicenseFromJson(licenseJson)
        } catch {
            return ActivationResult(
                success: false,
                errorMessage: "Failed to read license file: \(error.localizedDescription)"
            )
        }
    }

    /// Activates a license from JSON content (for embedded licenses)
    /// - Parameter licenseJson: JSON content of the license
    /// - Returns: Activation result with success status and message
    public static func activateLicenseFromJson(_ licenseJson: String) async -> ActivationResult {
        guard !licenseJson.trimmingCharacters(in: .whitespaces).isEmpty else {
            return ActivationResult(
                success: false,
                errorMessage: "License JSON cannot be empty"
            )
        }

        // Parse license
        guard let license = LicenseValidator.deserializeLicense(licenseJson) else {
            return ActivationResult(
                success: false,
                errorMessage: "Invalid license format"
            )
        }

        // Validate license
        let checkHardware = license.type == .standard
        let validation = LicenseValidator.validateLicense(license, checkHardware: checkHardware)

        guard validation.isValid else {
            return ActivationResult(
                success: false,
                errorMessage: validation.errorMessage ?? "License validation failed"
            )
        }

        // Store license
        queue.async(flags: .barrier) {
            _currentLicense = license
            _isLicensed = true
        }

        // Save to keychain
        await LicenseStorage.saveLicense(license)

        var message = "License activated successfully. Tier: \(license.tier.displayName)"
        if let warning = validation.warning {
            message += ". \(warning)"
        }

        return ActivationResult(
            success: true,
            message: message,
            license: license
        )
    }

    /// Validates the current license
    /// - Parameter forceOnline: Force online validation (not implemented)
    /// - Returns: Validation result
    public static func validateLicense(forceOnline: Bool = false) async -> ValidationResult {
        guard let license = currentLicense else {
            return ValidationResult(
                isValid: false,
                errorMessage: "No license found"
            )
        }

        let checkHardware = license.type == .standard
        return LicenseValidator.validateLicense(license, checkHardware: checkHardware)
    }

    /// Deactivates the current license
    /// - Returns: True if successful
    public static func deactivateLicense() async -> Bool {
        queue.async(flags: .barrier) {
            _currentLicense = nil
            _isLicensed = false
        }
        await LicenseStorage.clearLicense()
        return true
    }

    // MARK: - Helper Methods

    /// Gets days remaining on the license
    public static func getDaysRemaining() -> Int {
        return currentLicense?.daysUntilExpiration ?? 0
    }

    /// Checks if a specific feature is enabled
    public static func isFeatureEnabled(_ feature: String) -> Bool {
        switch feature.uppercased() {
        case "RSA": return isRSAAvailable
        case "AES": return isAESAvailable
        case "QUANTUM": return isQuantumAvailable
        case "PASSWORDHASHING": return isPasswordHashingAvailable
        default: return false
        }
    }

    /// Gets the hardware ID for this machine
    public static func getHardwareId() -> String {
        return HardwareIdGenerator.getHardwareId()
    }

    /// Gets a summary of the current license status
    public static func getLicenseStatus() -> String {
        guard isLicensed, let license = currentLicense else {
            return "No valid license found. Running in free mode with watermarks."
        }

        let tier = license.tier.displayName
        let customer = license.customer.email
        let expires = ISO8601DateFormatter().string(from: license.expiresAt)
        let days = license.daysUntilExpiration

        var status = "Licensed to: \(customer)\nTier: \(tier)\nExpires: \(expires) (\(days) days remaining)"

        if license.needsRenewal {
            status += "\n⚠️ License expires soon. Please renew."
        }

        return status
    }

    /// Checks if the license needs renewal (< 30 days remaining)
    public static func needsRenewal() -> Bool {
        return currentLicense?.needsRenewal ?? false
    }

    /// Gets the licensing portal URL
    public static func getLicensingPortalUrl() -> String {
        return "https://kyototech.jp/pricing"
    }

    /// Gets the support URL (contact form)
    public static func getSupportUrl() -> String {
        return "https://kyototech.jp/contact"
    }

    // MARK: - Initialization

    /// Loads stored license from keychain on startup
    public static func loadStoredLicense() async {
        if let license = await LicenseStorage.loadLicense() {
            let validation = LicenseValidator.validateLicense(license, checkHardware: license.type == .standard)
            if validation.isValid {
                queue.async(flags: .barrier) {
                    _currentLicense = license
                    _isLicensed = true
                }
            }
        }
    }
}
