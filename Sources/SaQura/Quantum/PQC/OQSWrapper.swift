// OQSWrapper.swift
// SaQura Swift Library
// Copyright (c) 2025-2026 KyotoTech LLC. All rights reserved.

import Foundation
import CLibOQS

/// Swift wrapper around the liboqs C API for KEM operations
internal final class OQSKem {
    /// Supported KEM algorithms
    enum Algorithm: String {
        case classicMcEliece6688128 = "Classic-McEliece-6688128"
        case classicMcEliece6960119 = "Classic-McEliece-6960119"
        case classicMcEliece8192128 = "Classic-McEliece-8192128"
        case frodokem640aes = "FrodoKEM-640-AES"
        case frodokem976aes = "FrodoKEM-976-AES"
        case frodokem1344aes = "FrodoKEM-1344-AES"
    }

    /// Errors specific to OQS operations
    enum OQSError: Error, LocalizedError {
        case algorithmNotSupported(String)
        case keyGenerationFailed(String)
        case encapsulationFailed(String)
        case decapsulationFailed(String)
        case invalidKeySize(expected: Int, actual: Int)
        case invalidCiphertextSize(expected: Int, actual: Int)

        var errorDescription: String? {
            switch self {
            case .algorithmNotSupported(let alg):
                return "OQS algorithm not supported: \(alg)"
            case .keyGenerationFailed(let msg):
                return "Key generation failed: \(msg)"
            case .encapsulationFailed(let msg):
                return "Encapsulation failed: \(msg)"
            case .decapsulationFailed(let msg):
                return "Decapsulation failed: \(msg)"
            case .invalidKeySize(let expected, let actual):
                return "Invalid key size: expected \(expected), got \(actual)"
            case .invalidCiphertextSize(let expected, let actual):
                return "Invalid ciphertext size: expected \(expected), got \(actual)"
            }
        }
    }

    private let algorithm: Algorithm
    private let kemPtr: UnsafeMutablePointer<OQS_KEM>

    /// Expected sizes for the current algorithm
    let publicKeyLength: Int
    let secretKeyLength: Int
    let ciphertextLength: Int
    let sharedSecretLength: Int

    init(algorithm: Algorithm) throws {
        self.algorithm = algorithm

        guard let ptr = OQS_KEM_new(algorithm.rawValue) else {
            throw OQSError.algorithmNotSupported(algorithm.rawValue)
        }
        self.kemPtr = ptr
        self.publicKeyLength = Int(ptr.pointee.length_public_key)
        self.secretKeyLength = Int(ptr.pointee.length_secret_key)
        self.ciphertextLength = Int(ptr.pointee.length_ciphertext)
        self.sharedSecretLength = Int(ptr.pointee.length_shared_secret)
    }

    deinit {
        OQS_KEM_free(kemPtr)
    }

    /// Generates a KEM key pair
    /// - Returns: Tuple of (publicKey, secretKey) as Data
    /// - Note: Classic McEliece key generation requires a large stack (>8MB).
    ///         This method automatically uses a dedicated thread with 8MB stack for CMCE algorithms.
    func generateKeyPair() throws -> (publicKey: Data, secretKey: Data) {
        if isCMCEAlgorithm {
            return try generateKeyPairOnLargeStack()
        }
        return try generateKeyPairDirect()
    }

    /// Encapsulates: generates a shared secret and ciphertext from a public key
    /// - Parameter publicKey: The recipient's public key
    /// - Returns: Tuple of (ciphertext, sharedSecret)
    func encapsulate(publicKey: Data) throws -> (ciphertext: Data, sharedSecret: Data) {
        guard publicKey.count == publicKeyLength else {
            throw OQSError.invalidKeySize(expected: publicKeyLength, actual: publicKey.count)
        }

        var ciphertext = Data(count: ciphertextLength)
        var sharedSecret = Data(count: sharedSecretLength)

        let result = ciphertext.withUnsafeMutableBytes { ctPtr in
            sharedSecret.withUnsafeMutableBytes { ssPtr in
                publicKey.withUnsafeBytes { pkPtr in
                    OQS_KEM_encaps(
                        kemPtr,
                        ctPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        ssPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        pkPtr.baseAddress?.assumingMemoryBound(to: UInt8.self)
                    )
                }
            }
        }

        guard result == OQS_SUCCESS else {
            throw OQSError.encapsulationFailed("OQS_KEM_encaps returned error")
        }

        return (ciphertext, sharedSecret)
    }

    /// Decapsulates: recovers the shared secret from a ciphertext using the secret key
    /// - Parameters:
    ///   - ciphertext: The encapsulated ciphertext
    ///   - secretKey: The recipient's secret key
    /// - Returns: The shared secret
    func decapsulate(ciphertext: Data, secretKey: Data) throws -> Data {
        guard ciphertext.count == ciphertextLength else {
            throw OQSError.invalidCiphertextSize(expected: ciphertextLength, actual: ciphertext.count)
        }

        guard secretKey.count == secretKeyLength else {
            throw OQSError.invalidKeySize(expected: secretKeyLength, actual: secretKey.count)
        }

        var sharedSecret = Data(count: sharedSecretLength)

        let result = sharedSecret.withUnsafeMutableBytes { ssPtr in
            ciphertext.withUnsafeBytes { ctPtr in
                secretKey.withUnsafeBytes { skPtr in
                    OQS_KEM_decaps(
                        kemPtr,
                        ssPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        ctPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        skPtr.baseAddress?.assumingMemoryBound(to: UInt8.self)
                    )
                }
            }
        }

        guard result == OQS_SUCCESS else {
            throw OQSError.decapsulationFailed("OQS_KEM_decaps returned error")
        }

        return sharedSecret
    }

    // MARK: - Private

    private var isCMCEAlgorithm: Bool {
        switch algorithm {
        case .classicMcEliece6688128, .classicMcEliece6960119, .classicMcEliece8192128:
            return true
        default:
            return false
        }
    }

    private func generateKeyPairDirect() throws -> (publicKey: Data, secretKey: Data) {
        var publicKey = Data(count: publicKeyLength)
        var secretKey = Data(count: secretKeyLength)

        let result = publicKey.withUnsafeMutableBytes { pkPtr in
            secretKey.withUnsafeMutableBytes { skPtr in
                OQS_KEM_keypair(
                    kemPtr,
                    pkPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    skPtr.baseAddress?.assumingMemoryBound(to: UInt8.self)
                )
            }
        }

        guard result == OQS_SUCCESS else {
            throw OQSError.keyGenerationFailed("OQS_KEM_keypair returned error")
        }

        return (publicKey, secretKey)
    }

    /// Runs CMCE keygen on a thread with 8MB stack to avoid stack overflow
    /// (iOS default stack is 512KB, CMCE needs >4MB)
    private func generateKeyPairOnLargeStack() throws -> (publicKey: Data, secretKey: Data) {
        let pkLen = publicKeyLength
        let skLen = secretKeyLength
        // Retain the pointer for use in the thread
        let kemPointer = kemPtr

        var resultPublicKey: Data?
        var resultSecretKey: Data?
        var resultError: Error?

        let semaphore = DispatchSemaphore(value: 0)

        // Use NSThread with custom stack size for simplicity
        let thread = Thread {
            var pk = Data(count: pkLen)
            var sk = Data(count: skLen)

            let status = pk.withUnsafeMutableBytes { pkPtr in
                sk.withUnsafeMutableBytes { skPtr in
                    OQS_KEM_keypair(
                        kemPointer,
                        pkPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        skPtr.baseAddress?.assumingMemoryBound(to: UInt8.self)
                    )
                }
            }

            if status == OQS_SUCCESS {
                resultPublicKey = pk
                resultSecretKey = sk
            } else {
                resultError = OQSError.keyGenerationFailed("OQS_KEM_keypair on large stack returned error")
            }

            semaphore.signal()
        }

        thread.stackSize = 8 * 1024 * 1024 // 8MB stack
        thread.qualityOfService = .userInitiated
        thread.start()

        semaphore.wait()

        if let error = resultError {
            throw error
        }

        guard let pk = resultPublicKey, let sk = resultSecretKey else {
            throw OQSError.keyGenerationFailed("CMCE keygen produced no output")
        }

        return (pk, sk)
    }
}
