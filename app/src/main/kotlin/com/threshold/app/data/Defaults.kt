package com.threshold.app.data

/**
 * Production defaults — single source of truth for wiring-boundary tests
 * (per Council iter-1 P0-11). Every parameter that crosses a module boundary
 * must be readable from here so tests can assert wiring correctness.
 *
 * family-locator LEARNINGS #20: protection mechanisms must be tested at the
 * wiring boundary with production defaults, not just in isolation.
 */
object Defaults {
    /** Heartbeat cadence: 24 hours (per build-contract §0). */
    const val HEARTBEAT_CADENCE_SEC: Long = 24L * 60 * 60

    /** Grace period before escalation begins: 1 hour (per build-contract §9). */
    const val GRACE_SEC: Long = 60 * 60

    /** Escalation step 1 (reminder to user): T+1h after missed beat. */
    const val STEP1_DELAY_SEC: Long = 60 * 60

    /** Escalation step 2 (soft ping to contact): T+24h. */
    const val STEP2_DELAY_SEC: Long = 24L * 60 * 60

    /** Escalation step 3 (release delivery): T+72h. */
    const val STEP3_DELAY_SEC: Long = 72L * 60 * 60

    /** Per-packet release-delay range (per iter-1 P0-22). */
    const val RELEASE_DELAY_MIN_SEC: Long = 24L * 60 * 60         // 24h
    const val RELEASE_DELAY_MAX_SEC: Long = 168L * 60 * 60       // 168h (1 week)
    const val RELEASE_DELAY_DEFAULT_SEC: Long = 72L * 60 * 60    // 72h

    /** Default relay list (per ops/relay-policy.md §2). Minimum 3 for multi-relay resilience. */
    val DEFAULT_RELAYS: List<String> = listOf(
        "wss://relay.damus.io",
        "wss://nos.lol",
        "wss://relay.bitid.nz"
    )

    /** Minimum relay count — app refuses to go below this (per relay-policy.md §6). */
    const val MIN_RELAYS: Int = 3

    /** Vault key derivation: BIP-39 24-word mnemonic. */
    const val BIP39_WORD_COUNT: Int = 24

    /** Constant-size heartbeat padding — DEFERRED to v1.1+ (per iter-1 §8.5). 0 = no padding. */
    const val HEARTBEAT_PADDING_BYTES: Int = 0

    /** Audit log: max events the in-app reader renders by default. */
    const val AUDIT_LOG_RENDER_LIMIT: Int = 100

    /** Watchdog silent countdown for duress events (per NIP §4.2). */
    const val DURESS_SILENT_COUNTDOWN_SEC: Long = 24L * 60 * 60
}
