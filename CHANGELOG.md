# Changelog

All notable changes to SaQura Swift will be documented in this file.

## [1.0.8] - 2026-05-18

### Fixed
- **`ApiLicense.is{AES,RSA,Quantum,PasswordHashing}Available` +
  `requiresWatermark` now honour the same tier-fallback semantics as
  .NET (`LicensingService.EnabledFeatures`) and Kotlin
  (`LicenseInfo.effectiveFeatures`).** The .NET production license
  server emits `.lic` files with `features: 0` for tier-based licenses
  (the tier carries the entitlement; the explicit bitmask is reserved
  for ad-hoc combinations). Before this fix the Swift gate accessors
  checked `currentLicense.features.contains(...)` directly, so customers
  with such licenses saw every gate closed regardless of tier (a paid
  Pro license read as Free). Discovered during iOS testing in
  TestApp E2E against the SMP-FLFL public sample license
  (`features:0, tier:3`). The bug is Day-1 (present since the first
  public Swift release), masked by the unit-test suite never exercising
  the `is*Available` accessors against a `features:0` fixture.
- **RSA-Hybrid wire format aligned to .NET canonical** (cross-platform alignment release). Swift
  + Kotlin now emit `[KeyLen:4 LE = 512][EncKey:512][Nonce:12][Tag:16][CT:N]`
  matching .NET. Decrypt is dual-shape: pre-Sess-136 `HYBR`-prefixed
  ciphertexts continue to decrypt via legacy branch (existing user data
  preserved).
- **`RSAKey.importPublicKey` + `importPrivateKey` auto-wrap raw PKCS#1
  keys** into SPKI/PKCS#8 wrappers when `SecKeyCreateWithData` returns
  nil (cross-platform PEM-import release). Cross-language interop with
  .NET-emitted raw PKCS#1 keys now succeeds without caller-side
  pre-wrapping.

### Added
- **`LicenseInfo.effectiveFeatures` computed property** (public).
  Returns explicit `features` bits if non-zero, otherwise derives from
  `tier` via `LicenseFeatures.features(for:)`. Mirrors Kotlin
  `LicenseInfo.effectiveFeatures` and .NET
  `LicensingService.EnabledFeatures`. Code consuming the public
  `LicenseInfo` API can now inspect the effective feature set without
  re-implementing the fallback.
- **5 regression tests** in `LicenseValidatorTests.swift`
  (`testEffectiveFeaturesFallsBackToTierWhenExplicitIsZero` et al.)
  pin the cross-platform-parity contract.

### Migration
- **No source changes required.** The `ApiLicense.is*Available` API
  shape is unchanged; only the underlying check is fixed. Callers that
  were working around the bug by reading `currentLicense?.features`
  directly should switch to `currentLicense?.effectiveFeatures` for
  consistent behaviour with .NET + Kotlin.

## [1.0.7] - 2026-05-12

### Added
- **Defense-in-Depth on the public Quantum API.** Mirrors .NET 1.0.7
  (commit `d849b6e`). Three caller-input checks fire BEFORE any async
  dispatch:
  - `Quantum.encrypt(_:publicKey:)` rejects empty AND all-zero public
    keys with `SaQuraError.invalidInput`. The all-zero check exists
    specifically for the failure mode where a caller defensively wipes
    a previously-cached key reference and then accidentally passes the
    cleared buffer back. A genuine FrodoKEM-22KB / McEliece-1MB public
    key being all-zero is ~2^-176000 probable — never a false positive,
    always a caller bug signal.
  - `Quantum.decrypt(_:privateKey:secret:)` rejects empty AND all-zero
    private keys; if `secret` is supplied, applies the same check to it.
    Empty ciphertext still short-circuits to `""` per the unconditional
    no-op contract.
- **Output sanity-net.** `Quantum.generateKeyPair`, `Quantum.encrypt`,
  and `Quantum.decrypt` each wrap the post-helper output through
  `CallerInputValidator.ensureKeyGenOutput` /
  `ensureEncryptOutput` / `ensureDecryptOutput`. The v1.0.6 typed-error
  fix should already throw on internal failure; this layer guards
  against future regressions where a backend returns silently-empty
  tuples instead. Output-side failures are reported as the existing
  `QuantumOperationError` cases (`.keyGeneration` / `.encryption` /
  `.decryption`) with an inner `SaQuraError.invalidInput` carrying the
  diagnostic detail.
- **`CallerInputValidator`** (`Sources/SaQura/Quantum/PQC/`, internal).
  New helper exposing the three input checks plus the three output
  sanity-nets, plus `generationFromKeyByte` and `strengthFromKeyByte`
  for diagnostic decoration on the typed errors. Also bumps `Tests/SaQuraTests/`
  with 19 new behavioural tests in `QuantumDefenseInDepthTests.swift`.

### Migration
- Callers passing wiped buffers will now receive
  `SaQuraError.invalidInput("...all-zero...")` instead of getting a
  silent `(nil, nil)` tuple downstream. Reload the key from your key
  store or pass a fresh copy.

## [1.0.6] - 2026-05-08

### Added
- `QuantumOperationError` — typed error surface for post-quantum failures.
  Mirrors the .NET `QuantumOperationException` hierarchy. Carries the
  requested `generation`, `strength` and `underlyingError` so callers can
  branch on context. The three discriminated cases are
  `.keyGeneration`, `.encryption`, and `.decryption`.

### Changed
- **Public Quantum API throws typed errors on failure.** `Quantum.generateKeyPair`,
  `Quantum.encrypt`, and `Quantum.decrypt` now wrap unexpected internal failures
  in `QuantumOperationError` instead of propagating raw `SaQuraError` /
  liboqs errors. Existing `LicenseException` and `SaQuraError.sizeLimitExceeded`
  paths (pre-checks for license / size limits) are unchanged.
- **Security hardening.** Internal license-gate diagnostics removed from
  Release builds. Internal diagnostic switches are now
  ignored in Release builds.

### Migration
- Callers catching `SaQuraError` for Quantum failures should add a
  `catch let error as QuantumOperationError` arm — the discriminator
  case (`.keyGeneration` / `.encryption` / `.decryption`), the
  `generation` / `strength` fields, and the `underlyingError` are
  available via pattern-matching or computed properties.

## [1.0.0] - 2026-04-20

### Added
- Initial public release of SaQura Swift.
- AES-256-GCM, RSA-4096 (with hybrid mode for large data), post-quantum
  encryption (FrodoKEM + Classic McEliece via liboqs), password hashing,
  digital signatures, and `.NET`-compatible licensing.
