package com.threshold.app.nostr

/**
 * Threshold NIP-3078 event kinds (per NIP.md §4).
 *
 * Per NIP §10 versioning: breaking changes use NEW kind numbers, not modifications
 * to existing ones, to preserve append-only audit-log readability across versions.
 *
 * Per Council iter-1 P0-11 (wiring-boundary tests): these constants are the
 * single source of truth for kind values. R8 keeps this class (see proguard-rules.pro).
 */
object EventKinds {
    /** Heartbeat (replaceable, parameterized). */
    const val HEARTBEAT = 30078
    /** Duress signal (replaceable, parameterized). */
    const val DURESS = 30079
    /** Escalation step (regular event). */
    const val ESCALATION = 30080
    /** Release packet (regular event). */
    const val RELEASE = 30081
    /** False-alarm cancellation (replaceable, parameterized). */
    const val FALSE_ALARM = 30082
    /** Audit log entry (replaceable, parameterized). */
    const val AUDIT = 30083
}

/**
 * The canonical `t` tag value on every Threshold event (per NIP §5).
 * Allows survivor clients to filter for Threshold events with a single tag.
 */
const val THRESHOLD_TAG = "threshold"
