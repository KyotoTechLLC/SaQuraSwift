# SaQura for Swift - User Guide

**Version:** 1.0.0
**Platforms:** iOS, macOS, tvOS, watchOS
**Last Updated:** January 2026

---

## Table of Contents

1. [Overview](#1-overview)
2. [Installation](#2-installation)
3. [License Activation](#3-license-activation)
4. [Encryption](#4-encryption)
5. [Password Security](#5-password-security)
6. [Digital Signatures](#6-digital-signatures)
7. [Quantum-Safe Encryption](#7-quantum-safe-encryption)
8. [License Tiers](#8-license-tiers)
9. [Troubleshooting](#9-troubleshooting)
10. [Support](#10-support)

---

## 1. Overview

SaQura is a professional cryptography library for Swift applications providing:

- **Symmetric Encryption** - Fast encryption for large data
- **Asymmetric Encryption** - Public/private key encryption
- **Password Security** - Secure password storage
- **Digital Signatures** - Data integrity verification
- **Quantum-Safe Encryption** - Future-proof security

### Supported Platforms

| Platform | Minimum Version | License Binding |
|----------|-----------------|-----------------|
| iOS | 15.0+ | Signature-based |
| macOS | 12.0+ | Hardware-bound |
| tvOS | 15.0+ | Signature-based |
| watchOS | 8.0+ | Signature-based |

### .NET Interoperability

SaQura for Swift is 100% compatible with SaQura for .NET. Data encrypted on one platform can be decrypted on the other. Use the same license files across both platforms.

---

## 2. Installation

### Swift Package Manager

Add SaQura to your project via Xcode:

1. File → Add Package Dependencies...
2. Enter the repository URL
3. Select the version

Or add to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/kyototech/SaQuraSwift.git", from: "1.0.0")
]
```

### Import

```swift
import SaQura
```

---

## 3. License Activation

### Check License Status

```swift
import SaQura

if ApiLicense.isLicensed {
    print("License is active")
    print("Tier: \(ApiLicense.currentTier)")
    print("Days remaining: \(ApiLicense.getDaysRemaining())")
} else {
    print("Running in free mode")
}
```

### Activate from License File

When you purchase a license, you receive `.lic` files. Activate them in your app:

```swift
import SaQura

// Activate from file path
let result = await ApiLicense.activateLicenseFile("/path/to/license.lic")

if result.success {
    print("License activated!")
} else {
    print("Activation failed: \(result.errorMessage ?? "Unknown error")")
}
```

### Embed License in Your App

For mobile apps, embed the license content directly:

```swift
import SaQura

// Read your license file content
let licenseJson = """
{
    "LicenseId": "...",
    "Tier": "Pro",
    ...
}
"""

let result = await ApiLicense.activateLicenseFromJson(licenseJson)

if result.success {
    print("Licensed: \(ApiLicense.currentTier)")
}
```

### Load Stored License on App Start

```swift
import SaQura

// Call on app startup to load previously activated license
await ApiLicense.loadStoredLicense()
```

### Check Feature Availability

```swift
import SaQura

if ApiLicense.isAESAvailable {
    // AES encryption is available
}

if ApiLicense.isRSAAvailable {
    // RSA encryption is available
}

if ApiLicense.isQuantumAvailable {
    // Quantum-safe encryption is available
}

if ApiLicense.isPasswordHashingAvailable {
    // Password hashing without watermark
}
```

### License File Types

Each purchase includes two license files:

| Type | File | Use Case |
|------|------|----------|
| **Standard** | `SaQura_{Tier}_standard.lic` | Development machines |
| **Distribution** | `SaQura_{Tier}_distribution.lic` | App Store distribution |

**For apps distributed to users, use the Distribution license.**

---

## 4. Encryption

### AES Encryption (Symmetric)

Best for encrypting large amounts of data with a shared key.

```swift
import SaQura

// Generate a secure key
let key = AESKey.newKey()

// Encrypt text
let encrypted = try await "Confidential data".encryptWithAES(key: key)

// Decrypt text
let decrypted = try await encrypted.decryptWithAES(key: key)
print(decrypted) // "Confidential data"
```

### Password-Based Encryption

Encrypt data using a password (no need to store a key).

```swift
import SaQura

let data = "Sensitive information"
let password = "MySecurePassword123!"

// Encrypt with password
let encrypted = try await data.encryptWithPassword(
    password: password,
    salt: "unique_salt_per_user"
)

// Decrypt with password
let decrypted = try await encrypted.decryptWithPassword(
    password: password,
    salt: "unique_salt_per_user"
)
```

### RSA Encryption (Asymmetric)

Best for encrypting small data or sharing secrets securely.

```swift
import SaQura

// Generate key pair
let (privateKey, publicKey) = try await RSAKey.newKeyPair()

// Encrypt with public key (anyone can encrypt)
let encrypted = try await "Secret message".encryptWithRSA(publicKey: publicKey)

// Decrypt with private key (only key owner can decrypt)
let decrypted = try await encrypted.decryptWithRSA(privateKey: privateKey)
```

### Encrypt Binary Data

```swift
import SaQura

let data = try Data(contentsOf: URL(fileURLWithPath: "document.pdf"))
let key = AESKey.newKey()

// Encrypt bytes
let encrypted = try await data.encryptWithAES(key: key)

// Decrypt bytes
let decrypted = try await encrypted.decryptWithAES(key: key)

try decrypted.write(to: URL(fileURLWithPath: "document_decrypted.pdf"))
```

---

## 5. Password Security

Securely store user passwords.

### Hash a Password

```swift
import SaQura

let password = "UserPassword123!"

// Create hash for storage
let hash = try await password.hashPassword()

// Store 'hash' in your database
```

### Verify a Password

```swift
import SaQura

let enteredPassword = "UserPassword123!"
let storedHash = "..." // From database

// Verify password
let isValid = try await enteredPassword.verifyPassword(hash: storedHash)

if isValid {
    print("Password correct!")
} else {
    print("Invalid password")
}
```

### Check Password Strength

```swift
import SaQura

let strength = "MyPassword123!".analyzePasswordStrength()

print("Score: \(strength.score)") // 0-100
print("Level: \(strength.level)") // .weak, .fair, .strong, .veryStrong
print("Suggestions: \(strength.suggestions)")
```

### Check if Rehashing is Needed

```swift
import SaQura

let storedHash = "..." // From database

// Check if hash needs updating (security improvements)
if storedHash.passwordHashNeedsRehash() {
    // Re-hash after successful login
    let newHash = try await password.hashPassword()
    // Update database with newHash
}
```

---

## 6. Digital Signatures

Verify data integrity and authenticity.

### Sign Data

```swift
import SaQura

// Generate key pair
let (privateKey, publicKey) = try await RSAKey.newKeyPair()

// Sign data with private key
let signature = try await "Important document content".signWithRSA(privateKey: privateKey)
```

### Verify Signature

```swift
import SaQura

let data = "Important document content"
let signature = "..." // Received signature
let publicKey = "..." // Sender's public key

// Verify signature
let isValid = try await data.verifyRSASignature(signature: signature, publicKey: publicKey)

if isValid {
    print("Signature is valid - data is authentic")
} else {
    print("Invalid signature - data may be tampered")
}
```

---

## 7. Quantum-Safe Encryption

Future-proof encryption resistant to advanced computing threats.

### Generate Keys

```swift
import SaQura

// Generate quantum-safe key pair
let (publicKey, privateKey) = try await Quantum.generateKeyPair(
    strength: .standard,
    generation: .gen6  // Recommended for mobile
)
```

### Encrypt with Quantum-Safe

```swift
import SaQura

let message = "Top secret information"

// Encrypt (returns secret + encrypted message)
let (secret, encryptedMessage) = try await message.encryptWithQuantum(publicKey: publicKey)

// Both values are needed for decryption
```

### Decrypt

```swift
import SaQura

// Decrypt using private key and secret
let decrypted = try await encryptedMessage.decryptWithQuantum(
    privateKey: privateKey,
    secret: secret
)
```

### Simplified API

```swift
import SaQura

// Encrypt (secret embedded in output)
let encrypted = try await "Message".encryptWithQuantumToBytes(publicKey: publicKey)

// Decrypt
let decrypted = try await encrypted.decryptWithQuantum(privateKey: privateKey)
```

### Security Levels

| Strength | Use Case |
|----------|----------|
| `.standard` | General applications (default) |
| `.medium` | Enhanced security |
| `.highest` | Maximum protection |

### Generations

All generations use **true post-quantum cryptography** (FrodoKEM + Classic McEliece), byte-compatible with the .NET SaQura library.

| Generation | Algorithm | Recommendation |
|------------|-----------|----------------|
| Gen2 | Classic McEliece + AES-CBC | Secure |
| Gen4 | FrodoKEM-1344 + AES-GCM | Secure |
| Gen5 | Classic McEliece + AES-CBC | Secure |
| Gen6 | FrodoKEM + AES-GCM | **Recommended for mobile** |
| Gen7 | RSA-4096 + FrodoKEM | Maximum security |

### Get Recommended Generation

```swift
import SaQura

let gen = Quantum.getRecommendedGeneration(forMobile: true, highestSecurity: false)
// Returns: .gen6
```

---

## 8. License Tiers

| Tier | Features |
|------|----------|
| **Free** | RSA (limited) + Password Hashing (with watermark) |
| **Basic** | RSA + Password Hashing (no watermark) |
| **Standard** | Basic + AES Encryption |
| **Pro** | Standard + Quantum-Safe Encryption |
| **Enterprise** | All features + Priority support |

### Feature Matrix

| Feature | Free | Basic | Standard | Pro |
|---------|------|-------|----------|-----|
| RSA (limited) | ✓ | ✓ | ✓ | ✓ |
| Password Hashing | ✓* | ✓ | ✓ | ✓ |
| AES Encryption | - | - | ✓ | ✓ |
| Quantum-Safe | - | - | - | ✓ |
| No Watermarks | - | ✓ | ✓ | ✓ |

*With watermark

---

## 9. Troubleshooting

### License Not Activating

1. Verify license file is not corrupted
2. Ensure license hasn't expired
3. Check file path is correct
4. For Distribution licenses, ensure it's embedded correctly

### Decryption Fails

1. Verify the correct key is used
2. Ensure data wasn't corrupted
3. Use the same encryption method for decryption
4. For cross-platform: verify both platforms use compatible versions

### Watermarks in Output

1. Activate a valid license
2. Check `ApiLicense.isLicensed` returns true
3. Verify your tier includes the feature

### Cross-Platform Issues

1. Ensure both .NET and Swift use the same key format
2. RSA keys must be in PEM format
3. Verify the data hasn't been modified in transit

### Mobile Platform Notes

On iOS, tvOS, and watchOS:
- Licenses are validated by signature and expiration only
- Hardware binding is not used (device IDs are not stable)
- Use Distribution license for App Store apps

---

## 10. Support

- **Website:** https://kyototech.co.jp
- **Support:** https://kyototech.co.jp/contact
- **Pricing:** https://kyototech.co.jp/pricing
- **Licensing Portal:** https://billing.kyototech.co.jp
- **Documentation:** This file

---

## Quick Reference

```swift
import SaQura

// Check license
let licensed = ApiLicense.isLicensed

// AES Encryption
let key = AESKey.newKey()
let enc = try await "data".encryptWithAES(key: key)
let dec = try await enc.decryptWithAES(key: key)

// RSA Encryption
let (priv, pub) = try await RSAKey.newKeyPair()
let enc = try await "data".encryptWithRSA(publicKey: pub)
let dec = try await enc.decryptWithRSA(privateKey: priv)

// Password Hashing
let hash = try await "password".hashPassword()
let valid = try await "password".verifyPassword(hash: hash)

// Digital Signature
let sig = try await "data".signWithRSA(privateKey: priv)
let valid = try await "data".verifyRSASignature(signature: sig, publicKey: pub)

// Quantum-Safe Encryption
let (pub, priv) = try await Quantum.generateKeyPair(strength: .standard, generation: .gen6)
let (secret, enc) = try await "data".encryptWithQuantum(publicKey: pub)
let dec = try await enc.decryptWithQuantum(privateKey: priv, secret: secret)
```

---

© 2025-2026 KyotoTech LLC. All rights reserved.
