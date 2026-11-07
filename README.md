# Threshold

**A local-first, end-to-end-encrypted dead-man's switch for everyday people.**

You store encrypted "release packets" in a vault on your phone — a password, a letter to your family, an insurance inventory, a healthcare directive, deployment keys, a will PDF. You set a heartbeat cadence (default: check in every 24 h). If you miss check-ins, the app escalates on a timer: T+1 h reminder to you, T+24 h soft ping to your trusted contact, T+72 h the chosen release packet is delivered to that contact via the public Nostr relay network — decrypted only by their pubkey.

**There is no server. There is no account. The app cannot be shut down by any company, including us.**

If the user dies, their secrets still flow to the people they chose, on the schedule they set, with the audit log they designed.

## ⚠️ Status: Shelved (2026-11-07)

Threshold was shelved at the principal's direction on 2026-11-07, in a **GREEN** state. The final release is **v1.0.2** — signed v1+v2+v3, cert `CN=Threshold Release, O=AutomatedLabor, C=US`, SHA-256 `092969405e448753e98a78c9ef77a9401e034969bdddc85a89f18ad6761f4691`. All three repos (`threshold`, `threshold-docs`, `build-learnings`) are **preserved, NOT archived**. The verification cron (Job A, ID 511151) continues to verify v1.0.2's integrity + signing every 20 min as a passive watchdog; Jobs B/C/D acknowledge-and-exit on their next tick per the stale-tick guard. **No new releases will be cut under this mandate.**

- Shelving decision + actions: [`threshold-docs/SHELVE-SESSION.md`](https://github.com/AutomatedLabor/threshold-docs/blob/main/SHELVE-SESSION.md)
- Final tally entry: [`threshold-docs/ops/release-status.md`](https://github.com/AutomatedLabor/threshold-docs/blob/main/ops/release-status.md)
- Cross-project retrospective (incl. §Shelving): [`build-learnings/projects/threshold/RETROSPECTIVE.md`](https://github.com/AutomatedLabor/build-learnings/blob/main/projects/threshold/RETROSPECTIVE.md)

**To resume:** send a new bootstrap prompt to a fresh agent. The cross-project `build-learnings` retrospective (especially §Shelving) is the operating manual — it records what was shelved, why, and what the resume procedure is. Do not assume a fresh agent has any of this session's state.

## What works (as of v1.0.2 — final release)

This is the first release. Per the build contract's "ship the loop on day one" rule, v1.0.0 ships the **full heartbeat → escalation → release loop** at minimum fidelity. v1.0.1 moved the build+sign+attach pipeline fully into CI, and v1.0.2 re-enabled v1 signing alongside v2+v3 after the "no certificates" false-negative incident — see [CHANGELOG.md](CHANGELOG.md) for the full release history:

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

## Known limitations (as of v1.0.2 — all carried to the final release)

Per Council iter-1 (see `threshold-docs/council-iter-1/REPORT.md`). **These limitations are present in the final release** — the deferred v1.1+ mitigations were never shipped:

- **M-of-N quorum is deferred to v1.1+.** v1.0.0 ships 1-of-1 packets only (per iter-1 P0-17, to remove a quorum race from v1.0.0).
- **Per-packet one-time recipient npubs are deferred to v1.1+.** v1.0.0 uses stable contact npubs. **v1.0.0 is NOT safe against state-actor adversaries who can subpoena relays** — see `THREAT-MODEL.md` §1.1.
- **Single watchdog** (Job E per `ops/watchdog.md`). v1.1+ will support multiple watchdogs (per iter-1 P0-5).
- **Android only.** iOS support is via a future web/desktop client (per `SURVIVOR-UX.md` §5.2).
- **Constant-size heartbeat padding** is deferred to v1.1+ (per iter-1 §8.5).
- **No StrongBox requirement for high-value packets** (per iter-1 P0-18, v1.1+ may require).

## Council

Per the build contract §6, all releases require multi-persona Council review. **All four planned iterations are complete** (records in the private docs repo):

- **iter-1** (architecture + threat-model audit, pre-code) — 22 findings (19 FIX / 2 DEFER / 3 ACCEPT), all P0s resolved before any production Kotlin.
- **iter-2** (post-ship audit) — accepted the minimal-fidelity UI with v1.1+ commitments; recorded the User Advocate's formal dissent on "shipped, not verified."
- **iter-3** (security deep-dive, Red Team lead) — attack-tree walk-through against the shipped build; no new P0s; v1.0.x accepted for the personal/family threat-model scope.
- **iter-4** (UX/survivor, User Advocate lead) — survivor flow walked step-by-step against the code; gaps filed as v1.1+ P0s.

The consolidated cross-project review lives at [`build-learnings/projects/threshold/COUNCIL-REVIEW.md`](https://github.com/AutomatedLabor/build-learnings/blob/main/projects/threshold/COUNCIL-REVIEW.md); per-iteration charters and reports at `threshold-docs/council-iter-{1..4}/`.

## Releases

All releases are attached to [GitHub Releases](https://github.com/AutomatedLabor/threshold/releases) with a `.sha256` sidecar and (from v1.0.1) SLSA build provenance:

| Release | Published (UTC) | versionCode | APK size | APK SHA-256 | Notes |
|---|---|---|---|---|---|
| [v1.0.2](https://github.com/AutomatedLabor/threshold/releases/tag/v1.0.2) **(final)** | 2026-11-07T08:23:18Z | 3 | 7,327,084 B | `09296940...6761f4691` | v1+v2+v3 signing; fixes the legacy-checker false negative |
| [v1.0.1](https://github.com/AutomatedLabor/threshold/releases/tag/v1.0.1) | 2026-11-07T06:36:23Z | 2 | 7,292,137 B | `3dd88460...19fdffd6` | first fully CI-built + signed release (SLSA provenance) |
| [v1.0.0](https://github.com/AutomatedLabor/threshold/releases/tag/v1.0.0) | 2026-11-07T05:41:45Z | 1 | see sidecar | see sidecar | first release; full loop at minimum fidelity |

### Install

1. Download `threshold-v1.0.2.apk` **and** `threshold-v1.0.2.apk.sha256` from the release page.
2. Verify integrity and signing (below).
3. Install on an Android 8.0+ device (minSdk 26), enabling install-from-unknown-sources for your browser/file manager if prompted.
4. On first launch, complete onboarding: write down the BIP-39 backup mnemonic when shown — the app refuses to seal the first release packet until backup is confirmed.

### Verify a downloaded release

```bash
# 1) Integrity — must print OK
sha256sum -c threshold-v1.0.2.apk.sha256

# 2) Signing — expect: Verifies, v1=true, v2=true, v3=true,
#    DN = CN=Threshold Release, O=AutomatedLabor, C=US
$ANDROID_HOME/build-tools/35.0.0/apksigner verify --print-certs --verbose \
    threshold-v1.0.2.apk
```

⚠️ **Do not use `keytool -printcert -jarfile` to judge whether the APK is signed.** It inspects v1 JAR signing only and reports "Not a signed jar file" for correctly-signed APKs whose v1 files are absent — the exact false negative that made v1.0.1 look "unsigned" and cost a release cycle. Use `apksigner` (as above); see [SECURITY.md](SECURITY.md) and the [post-mortem](https://github.com/AutomatedLabor/build-learnings/blob/main/projects/threshold/POST-MORTEM-shipped-not-installable.md).

## Repository layout

```
app/src/main/kotlin/com/threshold/app/
├── crypto/      Crypto.kt (crypto_box_seal + memzero), BIP39.kt (+ wordlist),
│                Schnorr.kt + NostrIdentity.kt + Bech32.kt (nsec/npub),
│                BIP39Words.kt
├── nostr/       Event.kt, EventKinds.kt (NIP-3078 kinds), EventSigner.kt,
│                RelayPool.kt (multi-relay pub/sub), Publisher.kt,
│                SurvivorClient.kt (catch-up + max-seen rule)
├── data/        Vault.kt, Packet.kt, Contact.kt, HeartbeatPolicy.kt,
│                Defaults.kt (single source of truth for wiring tests)
├── work/        HeartbeatWorker.kt, EscalationWorker.kt (WorkManager backstop)
├── MainActivity.kt, ThresholdApp.kt
app/src/test/kotlin/com/threshold/app/
├── crypto/      CryptoGoldenVectorsTest.kt (known plaintext→ciphertext),
│                CryptoFuzzTest.kt (10,000-pair round-trip)
├── nostr/       MaxSeenRuleTest.kt
├── audit/       AuditLogRenderTest.kt (renders 100 signed events, verified sigs)
├── wiring/      5 wiring-boundary tests — every cross-module parameter
│                asserted against Defaults (the family-locator keystone-bug class)
crypto-test-vectors.json   golden vectors consumed by CI as contract tests
.github/workflows/         build.yml, codeql.yml, osv-scanner.yml, gitleaks.yml
```

## Protocol (NIP-3078)

Threshold defines its wire protocol as a nostr NIP (private docs repo, `NIP.md`). Event kinds:

| Kind | Name | Semantics |
|---|---|---|
| `30078` | Heartbeat | replaceable, parameterized check-in (`d=threshold:heartbeat:<user-npub>`); encrypted cadence payload |
| `30079` | Duress | silent signal fired by the duress unlock; contact client starts a 24 h countdown, does NOT release immediately |
| `30080` | Escalation step | `step=1\|2\|3` — T+1h reminder, T+24h soft ping, T+72h release pointer |
| `30081` | Release packet | sealed to the contact's npub (`crypto_box_seal`); decryptable only by them |
| `30082` | False-alarm cancellation | replaces an escalation; contact client discards partial material |
| `30083` | Audit-log entry | append-only, signed; readable by any NIP-3078-aware client |

All payloads are encrypted; relays see only ciphertext, the publisher's npub, the recipient's npub (where applicable), the event kind, and `created_at`.

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
