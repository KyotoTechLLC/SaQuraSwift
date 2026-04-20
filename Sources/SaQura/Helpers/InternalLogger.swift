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

/// Check if running in debug mode
internal var isDebugMode: Bool {
    #if DEBUG
    return true
    #else
    return ProcessInfo.processInfo.environment["KYOTOTECH_DEBUG_MODE"] == "true"
    #endif
}
