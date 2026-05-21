// InternalLogger.swift
// SaQura Swift Library
// Copyright (c) 2025-2026 KyotoTech LLC. All rights reserved.

import Foundation
import os.log

/// Internal logging for SaQura library
internal enum InternalLogger {
    private static let subsystem = "jp.kyototech.saqura"
    private static let logger = Logger(subsystem: subsystem, category: "SaQura")

    /// Log levels
    enum Level {
        case debug
        case info
        case warning
        case error
    }

    /// Logs a message
    static func log(_ message: String, level: Level = .info, function: String = #function, file: String = #file) {
        #if DEBUG
        let fileName = (file as NSString).lastPathComponent
        let logMessage = "[\(fileName):\(function)] \(message)"

        switch level {
        case .debug:
            logger.debug("\(logMessage)")
        case .info:
            logger.info("\(logMessage)")
        case .warning:
            logger.warning("\(logMessage)")
        case .error:
            logger.error("\(logMessage)")
        }
        #endif
    }

    /// Logs an error
    static func log(_ error: Error, function: String = #function, file: String = #file) {
        log(error.localizedDescription, level: .error, function: function, file: file)
    }

    /// Logs a warning
    static func warning(_ message: String, function: String = #function, file: String = #file) {
        log("WARNING: \(message)", level: .warning, function: function, file: file)
    }

    /// Logs debug information
    static func debug(_ message: String, function: String = #function, file: String = #file) {
        log(message, level: .debug, function: function, file: file)
    }
}

/// Whether internal license-gate diagnostics are skipped.
/// Debug builds keep the convenience for in-house dev. Release builds
/// always return false by default so customers cannot bypass gates via
/// env var.
///
/// The unit-test override below is gated to internal visibility, so a
/// customer-facing binary cannot reach it through the public API
/// surface. It exists because release-mode test runs (`swift test -c
/// release`) compile out the `#if DEBUG` branch, which would otherwise
/// make every license-gated test path produce watermarked /
/// size-limited output the test wasn't written to handle. Same idiom
/// as Kotlin's `debugModeOverride` from M3.
internal var isDebugMode: Bool {
    if let override = debugModeOverride {
        return override
    }
    #if DEBUG
    return true
    #else
    return false
    #endif
}

/// Test-only override for `isDebugMode`. `nil` means "use the
/// `#if DEBUG` default" (the production setting); a non-`nil` value
/// forces the choice. Reset to `nil` after each test that touches it
/// — leaking state across tests is a footgun and resetting is cheap.
///
/// Same idiom as `ApiLicense.installForTesting` (the test-only hook
/// used by the License test fixtures).
internal var debugModeOverride: Bool?
