// CorpusConsumerTests.swift
// SaQura Swift Library — Phase 2.3 of the test corpus initiative
// Copyright (c) 2025-2026 KyotoTech LLC. All rights reserved.

import XCTest
import Foundation
@testable import SaQura

/// Walks every `_test_corpus/fixtures/<producer>/manifest.json` and
/// verifies each item with the Swift public API.
///
/// **Cross-platform hybrid + PBKDF2 caveat (see
/// `_test_corpus/BACKLOG.md`):** Swift's RSA-Hybrid wire format and
/// PBKDF2 JSON shape diverge from .NET's. The consumer SKIPS foreign-
/// producer fixtures for `rsa-4096-hybrid` and `pbkdf2-sha512`, logging
/// a clear "known incompatibility" message instead of failing. Phase
/// 2.5 will track this in a formal `crossPlatformInterop` manifest
/// field; for Phase 2.3 the skip-list is hardcoded here + in the .NET
/// consumer.
final class CorpusConsumerTests: XCTestCase {

    // The Swift LicenseValidator is `internal` — visible via @testable. We
    // mirror the .NET consumer's behavior: parse the .lic + verify the
    // signature + compare to the shared expected.json.

    override func setUp() {
        super.setUp()
        // Bypass license gates so all algorithms run without watermarking.
        debugModeOverride = true
    }

    override func tearDown() {
        debugModeOverride = nil
        super.tearDown()
    }

    func test_walkFullCorpus() async throws {
        let corpusRoot = try resolveCorpusRoot()
        let fixturesRoot = corpusRoot.appendingPathComponent("fixtures")
        guard FileManager.default.fileExists(atPath: fixturesRoot.path) else {
            XCTFail("no fixtures dir at \(fixturesRoot.path)")
            return
        }

        let producerDirs = try FileManager.default
            .contentsOfDirectory(at: fixturesRoot, includingPropertiesForKeys: nil)
            .filter { (try? $0.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) == true }
            .sorted { $0.lastPathComponent < $1.lastPathComponent }

        var consumedCount = 0
        var skippedCount = 0
        for producerDir in producerDirs {
            let manifestURL = producerDir.appendingPathComponent("manifest.json")
            guard FileManager.default.fileExists(atPath: manifestURL.path) else {
                print("CorpusConsumerTests: SKIP \(producerDir.lastPathComponent) — no manifest.json (incomplete fixture dir)")
                continue
            }

            let manifest = try JSONDecoder().decode(ConsumerManifest.self, from: try Data(contentsOf: manifestURL))
            print("CorpusConsumerTests: walking \(manifest.producer.library)_\(manifest.producer.version) (\(manifest.items.count) items)")

            for item in manifest.items {
                let locator = ConsumerLocator(producerDir: producerDir, manifest: manifest, item: item, corpusRoot: corpusRoot)
                if let skipReason = self.skipReason(for: item, manifest: manifest) {
                    print("  - SKIP \(item.path): \(skipReason)")
                    skippedCount += 1
                    continue
                }
                try await consume(locator)
                consumedCount += 1
            }
        }
        print("CorpusConsumerTests: consumed \(consumedCount), skipped \(skippedCount) across \(producerDirs.count) producer(s).")
    }

    // MARK: - Skip-list (foreign-producer known-incompatible)

    /// SPEC_VERSION-2 (Phase 2.5) skip-list: read `incompatibleWith` from
    /// the manifest item. If this consumer's library name is in the list
    /// AND the producer isn't us, skip.
    ///
    /// Backwards-compat fallback for SPEC_VERSION-1 fixtures (no
    /// `incompatibleWith` field): hardcoded list for the 4 historically-
    /// broken algorithms.
    private func skipReason(for item: ConsumerManifestItem, manifest: ConsumerManifest) -> String? {
        let producer = manifest.producer.library
        if producer == selfLibrary { return nil }

        if let incompat = item.incompatibleWith, incompat.contains(selfLibrary) {
            return "declared incompatibleWith=\(incompat) (producer=\(producer))"
        }

        if manifest.schemaVersion < 2 {
            // Pre-Phase-2.5 fallback. Drop once every historical fixture is
            // at schemaVersion ≥ 2.
            switch item.algorithm {
            case "aes-256-gcm" where producer == "net":
                return "SPEC_VERSION-1 fallback: cross-platform AES-GCM byte[] API divergence (see BACKLOG)"
            case "rsa-4096-hybrid" where producer == "net":
                return "SPEC_VERSION-1 fallback: cross-platform RSA-Hybrid wire format diverges (see BACKLOG)"
            case "pbkdf2-sha512" where producer == "net":
                return "SPEC_VERSION-1 fallback: cross-platform PBKDF2 JSON shape diverges (see BACKLOG)"
            default:
                return nil
            }
        }
        return nil
    }

    private let selfLibrary = "swift"

    // MARK: - Dispatch

    private func consume(_ loc: ConsumerLocator) async throws {
        switch loc.item.category {
        case "symmetric":
            try await consumeSymmetric(loc)
        case "rsa":
            try await consumeRsa(loc)
        case "quantum":
            try await consumeQuantum(loc)
        case "password":
            try consumePassword(loc)
        case "license":
            try consumeLicense(loc)
        default:
            XCTFail("\(loc): unknown category \(loc.item.category)")
        }
    }

    // MARK: - Symmetric

    private func consumeSymmetric(_ loc: ConsumerLocator) async throws {
        let json = try loadFixtureJson(loc)
        let algorithm = json["algorithm"] as? String ?? ""
        switch algorithm {
        case "aes-256-gcm":
            try await consumeAesGcm(loc, json: json)
        default:
            XCTFail("\(loc): unsupported symmetric algorithm \(algorithm)")
        }
    }

    private func consumeAesGcm(_ loc: ConsumerLocator, json: [String: Any]) async throws {
        let keyHex = json["keyHex"] as? String ?? ""
        let cipherHex = json["ciphertextHex"] as? String ?? ""
        let plaintextRef = json["plaintextRef"] as? String ?? ""

        guard let keyBytes = Data(hex: keyHex), let cipher = Data(hex: cipherHex) else {
            XCTFail("\(loc): invalid hex in AES-GCM fixture")
            return
        }
        let keyBase64 = keyBytes.toBase64()
        let expected = try Data(contentsOf: loc.corpusRoot.appendingPathComponent("plaintexts").appendingPathComponent(plaintextRef))

        let decrypted = try await cipher.decryptWithAES(key: keyBase64)
        XCTAssertEqual(decrypted, expected, "\(loc): AES-GCM decrypt mismatch")
    }

    // MARK: - RSA

    private func consumeRsa(_ loc: ConsumerLocator) async throws {
        let json = try loadFixtureJson(loc)
        let algorithm = json["algorithm"] as? String ?? ""
        switch algorithm {
        case "rsa-4096-oaep-sha256", "rsa-4096-hybrid":
            try await consumeRsaEncrypt(loc, json: json)
        case "rsa-4096-pss-sha256":
            try await consumeRsaVerifyPss(loc, json: json)
        default:
            XCTFail("\(loc): unsupported RSA algorithm \(algorithm)")
        }
    }

    private func consumeRsaEncrypt(_ loc: ConsumerLocator, json: [String: Any]) async throws {
        let pubKeyRef = json["pubKeyRef"] as? String ?? ""
        let cipherHex = json["ciphertextHex"] as? String ?? ""
        let plaintextRef = json["plaintextRef"] as? String ?? ""
        guard let cipher = Data(hex: cipherHex) else {
            XCTFail("\(loc): invalid hex in RSA fixture")
            return
        }
        let expected = try Data(contentsOf: loc.corpusRoot.appendingPathComponent("plaintexts").appendingPathComponent(plaintextRef))

        // Use the PKCS#8 encoding of the shared key (Swift's RSA importer
        // requires PKCS#8/SPKI; PKCS#1 is rejected — see BACKLOG §Phase-2.3).
        let privKeyPem = try String(contentsOf: loc.corpusRoot
            .appendingPathComponent("shared_keys")
            .appendingPathComponent("\(pubKeyRef).pkcs8.pem"))

        let decrypted = try RSACryptographyHelper.decrypt(cipher, privateKeyPEM: privKeyPem)
        XCTAssertEqual(decrypted, expected, "\(loc): RSA decrypt mismatch")
    }

    private func consumeRsaVerifyPss(_ loc: ConsumerLocator, json: [String: Any]) async throws {
        let pubKeyRef = json["pubKeyRef"] as? String ?? ""
        let sigHex = json["signatureHex"] as? String ?? ""
        let plaintextRef = json["plaintextRef"] as? String ?? ""
        guard let signature = Data(hex: sigHex) else {
            XCTFail("\(loc): invalid hex in RSA-PSS fixture")
            return
        }
        let data = try Data(contentsOf: loc.corpusRoot.appendingPathComponent("plaintexts").appendingPathComponent(plaintextRef))
        let pubKeyPem = try String(contentsOf: loc.corpusRoot
            .appendingPathComponent("shared_keys")
            .appendingPathComponent("\(pubKeyRef).pub.spki.pem"))

        let ok = try RSACryptographyHelper.verifySignature(data, signature: signature, publicKeyPEM: pubKeyPem)
        XCTAssertTrue(ok, "\(loc): RSA-PSS verify failed")
    }

    // MARK: - Quantum

    private func consumeQuantum(_ loc: ConsumerLocator) async throws {
        let binPath = loc.producerDir.appendingPathComponent(loc.item.path)
        let bytes = try Data(contentsOf: binPath)
        let saqf = try SaqfReader.parse(bytes)

        let cipherMessage = saqf.encryptedMessage
        let decrypted = try await Quantum.decrypt(cipherMessage, privateKey: saqf.privateKey, secret: saqf.encapsulatedSecret)
        let expectedStr = String(data: saqf.plaintext, encoding: .utf8) ?? ""
        XCTAssertEqual(decrypted, expectedStr, "\(loc): Quantum decrypt mismatch")
    }

    // MARK: - Password (PBKDF2)

    private func consumePassword(_ loc: ConsumerLocator) throws {
        let json = try loadFixtureJson(loc)
        let algorithm = json["algorithm"] as? String ?? ""
        switch algorithm {
        case "pbkdf2-sha512":
            let password = json["password"] as? String ?? ""
            let hashJson = json["hashJson"] as? String ?? ""
            let ok = try PasswordHasher.verify(password, hash: hashJson)
            XCTAssertTrue(ok, "\(loc): PBKDF2 verify failed")
            let wrong = (try? PasswordHasher.verify(password + "x", hash: hashJson)) ?? false
            XCTAssertFalse(wrong, "\(loc): PBKDF2 wrong-password verify incorrectly succeeded")
        default:
            XCTFail("\(loc): unsupported password algorithm \(algorithm)")
        }
    }

    // MARK: - License (decode_only)

    private func consumeLicense(_ loc: ConsumerLocator) throws {
        let stubData = try Data(contentsOf: loc.producerDir.appendingPathComponent(loc.item.path))
        let stub = try JSONSerialization.jsonObject(with: stubData) as? [String: Any] ?? [:]
        let licenseFile = stub["licenseFile"] as? String ?? ""
        let expectedKey = stub["expectedKey"] as? String ?? ""

        let sharedDir = loc.corpusRoot.appendingPathComponent("licenses")
        let licJson = try String(contentsOf: sharedDir.appendingPathComponent(licenseFile))

        guard let license = LicenseValidator.deserializeLicense(licJson) else {
            XCTFail("\(loc): Swift LicenseValidator.deserializeLicense returned nil for \(licenseFile)")
            return
        }
        let validation = LicenseValidator.validateLicense(license, checkHardware: false)
        XCTAssertTrue(validation.isValid,
            "\(loc): license signature verify failed via Swift LicenseValidator: \(validation.errorMessage ?? "unknown")")

        // Match against expected.json (canonical, produced by .NET reference implementation).
        let expectedRoot = try JSONSerialization.jsonObject(with: try Data(contentsOf: sharedDir.appendingPathComponent("expected.json"))) as? [String: Any] ?? [:]
        guard let expected = expectedRoot[expectedKey] as? [String: Any] else {
            XCTFail("\(loc): expected.json has no entry for \(expectedKey)")
            return
        }
        if let expId = expected["id"] as? String {
            XCTAssertEqual(license.id.uuidString.lowercased(), expId.lowercased(),
                "\(loc): id mismatch")
        }
        if let expEmail = expected["customerEmail"] as? String {
            XCTAssertEqual(license.customer.email, expEmail, "\(loc): customerEmail mismatch")
        }
        if let expTier = expected["tier"] as? Int {
            XCTAssertEqual(license.tier.rawValue, expTier, "\(loc): tier mismatch")
        }
        if let expType = expected["type"] as? Int {
            XCTAssertEqual(license.type.rawValue, expType, "\(loc): type mismatch")
        }
        if let expMaxAct = expected["maxActivations"] as? Int {
            XCTAssertEqual(license.maxActivations, expMaxAct, "\(loc): maxActivations mismatch")
        }
    }

    // MARK: - Helpers

    private func resolveCorpusRoot() throws -> URL {
        if let env = ProcessInfo.processInfo.environment["CORPUS_DIR"], !env.isEmpty {
            return URL(fileURLWithPath: env)
        }
        let fileURL = URL(fileURLWithPath: #filePath)
        var dir = fileURL.deletingLastPathComponent()
        while dir.path != "/" {
            let candidate = dir.appendingPathComponent("_test_corpus")
            if FileManager.default.fileExists(atPath: candidate.path) {
                return candidate
            }
            dir.deleteLastPathComponent()
        }
        XCTFail("could not locate _test_corpus/ via CORPUS_DIR env or upward search")
        throw NSError(domain: "CorpusConsumerTests", code: 1)
    }

    private func loadFixtureJson(_ loc: ConsumerLocator) throws -> [String: Any] {
        let data = try Data(contentsOf: loc.producerDir.appendingPathComponent(loc.item.path))
        return try JSONSerialization.jsonObject(with: data) as? [String: Any] ?? [:]
    }
}

// MARK: - Manifest decode (mirror of generator side)

struct ConsumerManifest: Decodable {
    let schemaVersion: Int
    let producer: ConsumerProducer
    let items: [ConsumerManifestItem]
}

struct ConsumerProducer: Decodable {
    let library: String
    let version: String
}

struct ConsumerManifestItem: Decodable {
    let path: String
    let category: String
    let algorithm: String
    let consumerExpectation: String
    let incompatibleWith: [String]?
}

struct ConsumerLocator: CustomStringConvertible {
    let producerDir: URL
    let manifest: ConsumerManifest
    let item: ConsumerManifestItem
    let corpusRoot: URL
    var description: String {
        return "\(producerDir.lastPathComponent)/\(item.path)"
    }
}

// MARK: - SAQF v1 reader (mirror of generator-side SaqfWriter)

struct SaqfFixture {
    let version: UInt8
    let generation: UInt8
    let strength: UInt8
    let plaintext: Data
    let publicKey: Data
    let privateKey: Data
    let sharedSecret: Data
    let encapsulatedSecret: Data
    let encryptedMessage: Data
}

enum SaqfReader {
    static func parse(_ bytes: Data) throws -> SaqfFixture {
        guard bytes.count >= 8 else { throw SaqfError.shortHeader }
        guard bytes[0] == 0x53, bytes[1] == 0x41, bytes[2] == 0x51, bytes[3] == 0x46 else {
            throw SaqfError.badMagic
        }
        let version = bytes[4]
        guard version == 1 else { throw SaqfError.unsupportedVersion(version) }
        let generation = bytes[5]
        let strength = bytes[6]

        var offset = 8
        let plaintext = try readField(bytes, offset: &offset)
        let publicKey = try readField(bytes, offset: &offset)
        let privateKey = try readField(bytes, offset: &offset)
        let sharedSecret = try readField(bytes, offset: &offset)
        let encapsulatedSecret = try readField(bytes, offset: &offset)
        let encryptedMessage = try readField(bytes, offset: &offset)
        return SaqfFixture(
            version: version, generation: generation, strength: strength,
            plaintext: plaintext, publicKey: publicKey, privateKey: privateKey,
            sharedSecret: sharedSecret, encapsulatedSecret: encapsulatedSecret,
            encryptedMessage: encryptedMessage
        )
    }

    private static func readField(_ bytes: Data, offset: inout Int) throws -> Data {
        guard offset + 4 <= bytes.count else { throw SaqfError.lenOob }
        let len = bytes.withUnsafeBytes { ptr -> UInt32 in
            return ptr.loadUnaligned(fromByteOffset: offset, as: UInt32.self).littleEndian
        }
        offset += 4
        let n = Int(len)
        guard offset + n <= bytes.count else { throw SaqfError.bytesOob }
        let slice = bytes[offset..<offset + n]
        offset += n
        return Data(slice)
    }

    enum SaqfError: Error {
        case shortHeader
        case badMagic
        case unsupportedVersion(UInt8)
        case lenOob
        case bytesOob
    }
}

// MARK: - Hex helper

extension Data {
    fileprivate init?(hex: String) {
        let cleaned = hex.replacingOccurrences(of: " ", with: "")
        guard cleaned.count % 2 == 0 else { return nil }
        var bytes = [UInt8]()
        bytes.reserveCapacity(cleaned.count / 2)
        var index = cleaned.startIndex
        while index < cleaned.endIndex {
            let next = cleaned.index(index, offsetBy: 2)
            guard let byte = UInt8(cleaned[index..<next], radix: 16) else { return nil }
            bytes.append(byte)
            index = next
        }
        self.init(bytes)
    }
}
