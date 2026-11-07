package com.threshold.app.data

import kotlinx.serialization.Serializable

/**
 * A trusted contact. Per NIP and THREAT-MODEL:
 *  - npub is the public Nostr key (bech32); used as `p` tag on release events.
 *  - displayName is LOCAL-ONLY — never published to relays (per THREAT-MODEL §4 A1.6).
 *  - verificationState: pending → verified (challenge-response per build-contract §9).
 *  - platform: surfaced in onboarding warning per iter-1 P0-19 (iOS contact → unrecoverable in v1.0.0).
 */
@Serializable
data class Contact(
    val npub: String,
    val displayName: String,
    val verificationState: VerificationState,
    val platform: ContactPlatform = ContactPlatform.UNKNOWN,
    val addedAt: Long,
    val verifiedAt: Long? = null
)

@Serializable
enum class VerificationState { PENDING, VERIFIED, REVOKED }

@Serializable
enum class ContactPlatform { ANDROID, IOS, DESKTOP, WEB, UNKNOWN }
