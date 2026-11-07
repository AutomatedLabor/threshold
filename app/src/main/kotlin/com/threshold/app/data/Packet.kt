package com.threshold.app.data

import kotlinx.serialization.Serializable

/**
 * A release packet — the actual sealed content the user wants delivered to a contact.
 * Per build-contract §0: a password, a letter to family, an insurance inventory,
 * a healthcare directive, deployment keys, a will PDF.
 *
 * v1.0.0 supports 1-of-1 packets only (per Council iter-1 P0-17; M-of-N deferred
 * to v1.1+ to remove a quorum race from v1.0.0).
 *
 * The encryptedPayload is the crypto_box_seal'd ciphertext of the user's content,
 * sealed to the contact's npub. The plaintext is NEVER logged, NEVER in Compose
 * state, NEVER in error messages (per build-contract §9 memory hygiene).
 */
@Serializable
data class Packet(
    val id: String,                    // UUID; matches the `packetId` tag on events
    val contactNpub: String,            // who this packet is sealed to
    val title: String,                  // local-only; encrypted inside the payload
    val contentType: String,           // "text/plain", "application/pdf", etc.
    val encryptedPayload: String,       // base64 of crypto_box_seal output
    val sealedAt: Long,                 // unix seconds
    val releaseDelaySec: Long,          // per-packet 24h–168h (per iter-1 P0-22)
    val revoked: Boolean = false,
    val revokedAt: Long? = null
)
