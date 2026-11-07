# Security Policy

## Supported version

**v1.0.2 (versionCode 3) is the final and only supported release.** Threshold was shelved on 2026-11-07 in a verified GREEN state; no further releases are planned under the current mandate (see the "Status: Shelved" banner in the [README](README.md)).

## Reporting a vulnerability

Please use **GitHub's private vulnerability reporting** on this repository (Security tab → "Report a vulnerability"). Do **not** open a public issue for anything that touches:

- the crypto path (`app/src/main/kotlin/com/threshold/app/crypto/`),
- key custody / the vault,
- nostr event signing or relay handling,
- the escalation / duress / release flow.

For protocol-level issues that affect third-party implementations, also reference **NIP-3078** (`threshold-docs/NIP.md` in the private `AutomatedLabor/threshold-docs` repo; contact the repository owner for access).

## Response expectations

This project is **shelved**: there is no active on-call, and response is best-effort by the maintainer. Issues in the crypto or escalation path will be triaged before any hypothetical resume of development; they will not be silently ignored, but do not expect a patched release under the current mandate.

## Known deferred risks (accepted at ship, documented, not secret)

These are recorded so nobody has to rediscover them:

1. **Not hardened against state-actor adversaries.** Contact npubs are visible on release events' `p` tags; a relay operator (or a party able to subpoena relay logs) can correlate contacts. Council iter-1 P0-2 scoped v1.0.x to personal/family threat models. Per-packet one-time recipient npubs are the v1.1+ mitigation (never shipped).
2. **M-of-N quorum never shipped.** v1.0.x is 1-of-1 packets only (iter-1 P0-17 deferred quorum to remove a race).
3. **The nsec is not hardware-backed in v1.0.x.** It lives in the vault, encrypted at rest with the BIP-39-derived key; a root-level attacker on the device could extract it. StrongBox enforcement for high-value packets was deferred (iter-1 P0-18).
4. **Single watchdog assumption** (iter-1 P0-5) and **no constant-size heartbeat padding** (metadata leak of cadence via event size, iter-1 §8.5).

Full detail: `THREAT-MODEL.md` in the private docs repo; `council-iter-3/REPORT.md` contains the Red-Team attack-tree walk-through against the shipped code.

## Verifying a release (what to check, and with which tool)

- Integrity: `sha256sum -c threshold-v1.0.2.apk.sha256` — must match `092969405e448753e98a78c9ef77a9401e034969bdddc85a89f18ad6761f4691`.
- Signing: `apksigner verify --print-certs --verbose threshold-v1.0.2.apk` — expect `Verifies`, v1=true, v2=true, v3=true, `CN=Threshold Release, O=AutomatedLabor, C=US`, cert SHA-256 `188da80dd8abac9d3f6969c0ac58b03e03115a58ce4234f50c4002e15cdce297`.
- **Do not** use `keytool -printcert -jarfile` to judge installability: it inspects v1 JAR signing only and reports "Not a signed jar file" for properly-signed v2/v3-era APKs. This exact false negative cost the v1.0.1 release cycle ([post-mortem](https://github.com/AutomatedLabor/build-learnings/blob/main/projects/threshold/POST-MORTEM-shipped-not-installable.md)).
