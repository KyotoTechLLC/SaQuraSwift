# SaQura for Swift

Enterprise-grade cryptography library for iOS, macOS, tvOS, and watchOS. Swift implementation of the [SaQura .NET Library](https://www.nuget.org/packages/SaQura) by KyotoTech LLC.

## Features

- **AES-256 Encryption** - Fast symmetric encryption for any data size
- **RSA Encryption** - Asymmetric encryption with automatic hybrid mode for large data
- **Password Security** - Industry-standard secure password storage
- **Digital Signatures** - Data integrity and authenticity verification
- **Quantum-Safe Encryption** - Future-proof security against advanced threats
- **Licensing System** - Compatible with .NET SaQura license files

## Requirements

- iOS 15.0+ / macOS 12.0+ / tvOS 15.0+ / watchOS 8.0+
- Swift 5.9+
- Xcode 15.0+

## Installation

### Swift Package Manager

Add SaQura to your project via Xcode:
1. File → Add Package Dependencies...
2. Enter the repository URL
3. Select the version

Or add to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/KyotoTechLLC/SaQuraSwift.git", from: "1.0.6")
]
```

## Quick Start

### AES Encryption

```swift
import SaQura

// Generate a new key
let key = AESKey.newKey()

// Encrypt
let encrypted = try await "Hello, SaQura!".encryptWithAES(key: key)

// Decrypt
let decrypted = try await encrypted.decryptWithAES(key: key)
print(decrypted) // "Hello, SaQura!"

// Password-based encryption
let encrypted = try await "Secret".encryptWithPassword(
    password: "my_password",
    salt: "random_salt"
)
```

### RSA Encryption

```swift
import SaQura

// Generate key pair
let (privateKey, publicKey) = try await RSAKey.newKeyPair()

// Encrypt (automatically uses hybrid encryption for large data)
let encrypted = try await "Secret message".encryptWithRSA(publicKey: publicKey)

// Decrypt
let decrypted = try await encrypted.decryptWithRSA(privateKey: privateKey)

// Digital signatures
let signature = try await "Sign this".signWithRSA(privateKey: privateKey)
let isValid = try await "Sign this".verifyRSASignature(signature: signature, publicKey: publicKey)
```

### Password Security

```swift
import SaQura

// Hash a password
let hash = try await "password123".hashPassword()

// Verify a password
let isValid = try await "password123".verifyPassword(hash: hash)

// Check password strength
let strength = "password123".analyzePasswordStrength()
print(strength.score) // 0-100
print(strength.level) // .weak, .fair, .strong, .veryStrong
print(strength.suggestions) // ["Add special characters", ...]
```

### Quantum-Safe Encryption

```swift
import SaQura

// Generate quantum-safe key pair
let (publicKey, privateKey) = try await Quantum.generateKeyPair(
    strength: .standard,
    generation: .gen6  // Recommended for mobile
)

// Encrypt
let (secret, encrypted) = try await "Quantum safe!".encryptWithQuantum(publicKey: publicKey)

// Decrypt
let decrypted = try await encrypted.decryptWithQuantum(
    privateKey: privateKey,
    secret: secret
)

// Simplified API (secret embedded in output)
let encrypted = try await "Message".encryptWithQuantumToBytes(publicKey: publicKey)
let decrypted = try await encrypted.decryptWithQuantum(privateKey: privateKey)
```

## Security Levels

### Quantum-Safe Generations

All generations use **true post-quantum cryptography** (FrodoKEM + Classic McEliece via liboqs), byte-compatible with the .NET SaQura library (BouncyCastle).

| Generation | Algorithm | Symmetric | Recommended Use |
|------------|-----------|-----------|-----------------|
| Gen2 | Classic McEliece | AES-CBC + HMAC | General purpose |
| Gen4 | FrodoKEM-1344 | AES-GCM | Desktop/Server |
| Gen5 | Classic McEliece | AES-CBC + HMAC | High security |
| Gen6 | FrodoKEM | AES-GCM | **Mobile (Recommended)** |
| Gen7 | RSA-4096 + FrodoKEM | AES-GCM | Maximum security |

### Strength Levels

| Strength | Description |
|----------|-------------|
| `.standard` | General purpose (default) |
| `.medium` | Enhanced security |
| `.highest` | Maximum protection |

```swift
// Get recommended generation
let gen = Quantum.getRecommendedGeneration(forMobile: true, highestSecurity: false)
// Returns: .gen6
```

## Licensing

SaQura offers tiered licensing:

| Feature | Free | Basic | Standard | Pro |
|---------|------|-------|----------|-----|
| RSA (limited) | ✓ | ✓ | ✓ | ✓ |
| Password Security | ✓* | ✓ | ✓ | ✓ |
| AES Encryption | - | - | ✓ | ✓ |
| Quantum-Safe | - | - | - | ✓ |
| No Watermarks | - | ✓ | ✓ | ✓ |

*With watermark

### Activate a License

When you purchase a license, you receive license files (`.lic`). Activate them in your app:

```swift
import SaQura

// From license file path
let result = await ApiLicense.activateLicenseFile("/path/to/license.lic")

// Or embed license content in your app (recommended for App Store)
let result = await ApiLicense.activateLicenseFromJson(licenseJson)

if result.success {
    print("Licensed: \(ApiLicense.currentTier)")
}

// Check feature availability
if ApiLicense.isQuantumAvailable {
    // Use quantum-safe encryption
}
```

### License Types

Each purchase includes two license files:

| Type | File | Use Case |
|------|------|----------|
| **Standard** | `SaQura_{Tier}_standard.lic` | Development machines |
| **Distribution** | `SaQura_{Tier}_distribution.lic` | App Store distribution |

**For apps distributed to end users, use the Distribution license.**

### Load Stored License

```swift
// Call on app startup to load previously activated license
await ApiLicense.loadStoredLicense()
```

## .NET Interoperability

SaQura for Swift is 100% compatible with SaQura for .NET. Data encrypted on one platform can be decrypted on the other:

```csharp
// .NET
var encrypted = await "Hello".EncryptWithAESAsync(key);
// Send 'encrypted' to iOS app
```

```swift
// Swift
let decrypted = try await encrypted.decryptWithAES(key: key)
// decrypted == "Hello"
```

## Documentation

- **User Guide**: See `USER_GUIDE.md` for detailed usage instructions
- **API Documentation**: [https://kyototech.co.jp/docs/saqura](https://kyototech.co.jp/docs/saqura)

## License

Commercial license required for production use. Free tier available for evaluation and development.

- **Purchase**: [https://kyototech.co.jp/pricing](https://kyototech.co.jp/pricing)
- **Support**: [https://kyototech.co.jp/contact](https://kyototech.co.jp/contact)
- **Licensing Portal**: [https://billing.kyototech.co.jp](https://billing.kyototech.co.jp)

## Links

- [NuGet Package (.NET)](https://www.nuget.org/packages/SaQura)
- [KyotoTech Website](https://kyototech.co.jp)

---

© 2025-2026 KyotoTech LLC. All rights reserved.
