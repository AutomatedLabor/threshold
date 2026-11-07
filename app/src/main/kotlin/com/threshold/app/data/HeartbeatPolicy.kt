package com.threshold.app.data

import kotlinx.serialization.Serializable

/**
 * The user's heartbeat policy. Encrypted to self in `kind:30078` content (per NIP §4.1).
 *
 * One policy per packet the user wants released on missed-heartbeat.
 * Each policy has its own escalation ladder (per build-contract §9).
 */
@Serializable
data class HeartbeatPolicy(
    val cadenceSec: Long,                // default 24h (Defaults.HEARTBEAT_CADENCE_SEC)
    val graceSec: Long,                  // default 1h (Defaults.GRACE_SEC)
    val policies: List<PacketReleasePolicy>
)

@Serializable
data class PacketReleasePolicy(
    val packetId: String,
    val step1DelaySec: Long,             // T+1h: reminder to user (Defaults.STEP1_DELAY_SEC)
    val step2DelaySec: Long,             // T+24h: soft ping to contact
    val step3DelaySec: Long              // T+72h: release delivery
)
