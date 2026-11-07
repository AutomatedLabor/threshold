# Changelog

All notable changes to Threshold. Dates are UTC (release publication time).
Format loosely follows [Keep a Changelog](https://keepachangelog.com/); versioning is `MAJOR.MINOR.PATCH` with `versionCode` monotonic for Android.

Threshold was **shelved on 2026-11-07** at the principal's direction, in a verified GREEN state. **v1.0.2 is the final release.** See [`SHELVE-SESSION.md`](https://github.com/AutomatedLabor/threshold-docs/blob/main/SHELVE-SESSION.md) in the (private) docs repo for the decision record.

---

## [1.0.2] — 2026-11-07 (final release)

**Tag:** `v1.0.2` · commit `3e00e81` · versionCode **3**, versionName `1.0.2` · published 2026-11-07T08:23:18Z

### Fixed
- **Signing compatibility: v1 signing re-enabled alongside v2+v3.** v1.0.1 shipped v2+v3-only (`enableV1Signing=false`), which is valid for Android 7+ installers but leaves `META-INF/` without v1 JAR cert files — so `keytool -printcert -jarfile`, `jarsigner`, zip viewers, and web "APK signature checkers" all report "no certificates" (a false negative that blocked a real device installation and cost a release cycle). v1.0.2 signs with **v1 + v2 + v3** so both modern Android verifiers and legacy inspection tools see the certificate. Full incident write-up: [`POST-MORTEM-shipped-not-installable.md`](https://github.com/AutomatedLabor/build-learnings/blob/main/projects/threshold/POST-MORTEM-shipped-not-installable.md).

### Verification (independently checkable)
- APK: `threshold-v1.0.2.apk`, **7,327,084 bytes**
- SHA-256: `092969405e448753e98a78c9ef77a9401e034969bdddc85a89f18ad6761f4691` (matches official `.sha256` sidecar and the persisted baseline — triple-verified by heartbeat runs #7–#9)
- Signing: `apksigner verify --print-certs --verbose` → `Verifies`, v1=true, v2=true, v3=true
- Signer: `CN=Threshold Release, O=AutomatedLabor, C=US`, cert SHA-256 `188da80dd8abac9d3f6969c0ac58b03e03115a58ce4234f50c4002e15cdce297`
- CI on the tag: build + 40 unit tests + R8 + size budget + OSV-Scanner + CodeQL + Gitleaks all green; APK + `.sha256` sidecar + SLSA provenance attached

---

## [1.0.1] — 2026-11-07

**Tag:** `v1.0.1` · commit `e572b06` · versionCode **2**, versionName `1.0.1` · published 2026-11-07T06:36:23Z

### Changed
- First release **built, signed, and attached entirely by CI** (keystore injected from GitHub Actions secrets, never on the agent): build → 40 unit tests → R8 → sign → `apksigner` v2+v3 verify → attach APK + `.sha256` + SLSA build provenance. This closed the v1.0.0 gap where the released binary was not the tested binary.
- versionCode bumped 1 → 2, versionName 1.0.0 → 1.0.1.

### Verification
- APK: `threshold-v1.0.1.apk`, **7,292,137 bytes**
- SHA-256: `3dd884607878ba5abee9b3566b31a3db0746f2f4c7d30d41f608d8c419fdffd6`

### Known issue (fixed in 1.0.2)
- v2+v3-only signing (v1 disabled) caused legacy checkers to report "no certificates"; a real-device install failed as a result. The APK was, in fact, correctly signed — the incident was a **tooling false negative** and drove the signing-verification upgrades in the watchdog (heartbeat v3 verifies `apksigner` scheme flags + cert DN + cert SHA-256, not just the hash).

---

## [1.0.0] — 2026-11-07

**Tag:** `v1.0.0` · versionCode **1**, versionName `1.0.0` · published 2026-11-07T05:41:45Z

### Added
- First release, shipping the **full heartbeat → escalation → release loop** at minimum fidelity per the build contract's "ship the loop on day one" rule:
  - **Vault**: local-first, encrypted at rest, BIP-39 mnemonic backup (mandatory before first packet).
  - **Identity**: secp256k1 (BIP-340 Schnorr) nsec/npub, stored in the vault.
  - **Crypto**: libsodium `crypto_box_seal` packet encryption; pure-Kotlin BIP-340 Schnorr event signing; golden-vector contract tests + 10,000-pair property-based round-trip fuzzing (`crypto-test-vectors.json`).
  - **Nostr transport**: multi-relay publish/subscribe (default 3 well-known public relays).
  - **Heartbeat** `kind:30078`, **escalation** `kind:30080` (T+1h/24h/72h ladder), **release** `kind:30081`, **false-alarm cancellation** `kind:30082`, **audit log** `kind:30083` (append-only).
  - **Survivor client**: catch-up phase + max-seen rule (Council iter-1 P0-4 + P0-15).
- Council iter-1 (22 findings: 19 FIX / 2 DEFER / 3 ACCEPT) resolved **before** any production Kotlin.
- 18 wiring-boundary tests asserting every parameter that crosses a module boundary.
- CI: build + tests + R8 smoke + size budget + OSV-Scanner + CodeQL + Gitleaks, all required checks on `main`.

### Fixed (same day, post-tag)
- Initial CI run on the tag was red: keystore secret missing (unsigned APK) and an invalid OSV-scanner action pin. Fixed within the verification tick (secrets uploaded, action pinned to `@v1.9.2` with SARIF upload); re-run green. No user intervention.

---

## Protocol note for all releases

Release event kinds are defined in **NIP-3078** (`threshold-docs/NIP.md`, private repo): `30078` heartbeat, `30079` duress, `30080` escalation step, `30081` release packet, `30082` false-alarm cancellation, `30083` audit-log entry. All payloads are encrypted; relays see only ciphertext, npubs, event kind, and `created_at`.
