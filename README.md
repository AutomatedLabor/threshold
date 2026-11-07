# Threshold

**A local-first, end-to-end-encrypted dead-man's switch for everyday people.**

You store encrypted "release packets" in a vault on your phone — a password, a letter to your family, an insurance inventory, a healthcare directive, deployment keys, a will PDF. You set a heartbeat cadence (default: check in every 24 h). If you miss check-ins, the app escalates on a timer: T+1 h reminder to you, T+24 h soft ping to your trusted contact, T+72 h the chosen release packet is delivered to that contact via the public Nostr relay network — decrypted only by their pubkey.

**There is no server. There is no account. The app cannot be shut down by any company, including us.**

If the user dies, their secrets still flow to the people they chose, on the schedule they set, with the audit log they designed.

## v1.0.0 — what works

This is the first release. Per the build contract's "ship the loop on day one" rule, v1.0.0 ships the **full heartbeat → escalation → release loop** at minimum fidelity:

- **Vault**: local-first, encrypted at rest, BIP-39 mnemonic backup (mandatory before first packet).
- **Identity**: secp256k1 (BIP-340 Schnorr) nsec/npub. Stored in the vault.
- **Crypto**: libsodium `crypto_box_seal` for all packet encryption; pure-Kotlin BIP-340 Schnorr for event signing.
- **Nostr transport**: multi-relay publish/subscribe (default 3 well-known public relays).
- **Heartbeat**: signed `kind:30078` events; one-tap check-in; WorkManager backstop.
- **Escalation**: signed `kind:30080` events; T+1h/24h/72h ladder per build-contract §9.
- **Release**: signed `kind:30081` events sealed to contact npub.
- **False-alarm cancellation**: signed `kind:30082` events.
- **Audit log**: signed `kind:30083` events (append-only).
- **Survivor client**: catch-up phase + max-seen rule (per iter-1 P0-4 + P0-15).

## v1.0.0 — known limitations

Per Council iter-1 (see `threshold-docs/council-iter-1/REPORT.md`):

- **M-of-N quorum is deferred to v1.1+.** v1.0.0 ships 1-of-1 packets only (per iter-1 P0-17, to remove a quorum race from v1.0.0).
- **Per-packet one-time recipient npubs are deferred to v1.1+.** v1.0.0 uses stable contact npubs. **v1.0.0 is NOT safe against state-actor adversaries who can subpoena relays** — see `THREAT-MODEL.md` §1.1.
- **Single watchdog** (Job E per `ops/watchdog.md`). v1.1+ will support multiple watchdogs (per iter-1 P0-5).
- **Android only.** iOS support is via a future web/desktop client (per `SURVIVOR-UX.md` §5.2).
- **Constant-size heartbeat padding** is deferred to v1.1+ (per iter-1 §8.5).
- **No StrongBox requirement for high-value packets** (per iter-1 P0-18, v1.1+ may require).

## Council

Per the build contract §6, all releases require multi-persona Council review. Council iter-1 (architecture + threat model audit, pre-code) is complete; iter-2 (post-ship audit), iter-3 (security deep-dive), and iter-4 (UX/survivor) follow per `threshold-docs/ops/cron-registry.md`.

## Documentation

The complete design documentation lives in the (private) [threshold-docs](https://github.com/AutomatedLabor/threshold-docs) repo:

- `THREAT-MODEL.md` — asset inventory, adversary model, attack trees, trust boundaries, failure modes, false-positive runbook.
- `NIP.md` — NIP-3078 (Threshold Nostr event kinds 30078-30083).
- `SURVIVOR-UX.md` — the 6-step survivor flow, 9 edge cases, printable survivor instructions template.
- `ops/KILL-SWITCH.md`, `ops/recovery.md`, `ops/relay-policy.md`, `ops/watchdog.md`, `ops/cron-registry.md`.

## Build & verify

```bash
# Local build (assumes JDK 17 + Android SDK 34 + build-tools 34.0.0)
./gradlew :app:assembleDebug
./gradlew :app:testDebugUnitTest

# Release build (signed if keystore configured)
./gradlew :app:assembleRelease

# Verify release APK signature
$ANDROID_HOME/build-tools/34.0.0/apksigner verify --print-certs --verbose \
    app/build/outputs/apk/release/app-release.apk
# Expect: "Verifies", v2=true, v3=true, CN=Threshold Release
```

## CI

GitHub Actions on every push and tag:
- `build.yml` — Android build + unit tests + R8 smoke + size budget + release signing + APK signature verification (v2+v3 required) + APK + .sha256 sidecar attached to GitHub Release.
- `codeql.yml` — static analysis for Kotlin + Java.
- `osv-scanner.yml` — vulnerability scan against pinned dependency manifest.
- `gitleaks.yml` — secret-scanning (blocks the literal PAT from being committed).

All four are required status checks on `main`.

## Disclaimer

**Threshold is not a lawyer, a will, or a substitute for estate planning advice. Consult a qualified attorney for legal matters.** (Per build-contract §10, this disclaimer is shown in onboarding AND in the release-packet creation flow.)

## License

MIT — see [LICENSE](LICENSE).

## Acknowledgments

- **family-locator** (`AutomatedLabor/family-locator`) — proven AGP 8.5.2 + Kotlin 2.0 + Lazysodium + secp256k1 stack, which Threshold adapts.
- **build-learnings** — the project-agnostic learnings repo (the cross-project memory).
