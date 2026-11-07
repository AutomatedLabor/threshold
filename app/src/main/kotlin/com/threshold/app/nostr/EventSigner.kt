package com.threshold.app.nostr

import com.threshold.app.crypto.Schnorr
import java.security.MessageDigest

/**
 * NIP-01 event signer using pure-Kotlin BIP-340 Schnorr.
 *
 * Per NIP §6 conformance: every event signature MUST verify against the
 * publisher's npub. Drop on failure. No exceptions.
 *
 * Per build-contract §9: heartbeat signing is nsec-signed kind:30078 events.
 *
 * Sign: take the event's canonical id (SHA-256 of the canonical JSON array),
 *       sign with the publisher's 32-byte nsec, set `id` and `sig` fields.
 * Verify: recompute the canonical id, verify the signature against the pubkey.
 */
object EventSigner {

    /** Sign an unsigned event (id set, sig empty) and return a signed event (sig filled). */
    fun sign(event: NostrEvent, privateKey: ByteArray): NostrEvent {
        require(privateKey.size == 32) { "private key must be 32 bytes" }
        require(event.id == event.computeIdHex()) { "event.id does not match computeIdHex(); pre-compute the id before signing" }
        // BIP-340 Schnorr sign over the 32-byte id (interpreted as bytes, not hex).
        val idBytes = hexToBytes(event.id)
        val sigBytes = Schnorr.sign(privateKey, idBytes)
        return event.copy(sig = bytesToHex(sigBytes))
    }

    /**
     * Verify a signed event's signature against its pubkey.
     * Per NIP §6: drop on failure. This method does NOT throw — returns false.
     *
     * Per iter-1 P0-4 (clock-rollback defence): caller is also expected to check
     * that createdAt > max-seen for the pubkey (see [SurvivorClient]).
     */
    fun verify(event: NostrEvent, publicKeyXOnlyHex: String): Boolean {
        if (event.pubkey != publicKeyXOnlyHex) return false
        // First check id matches (catches tampering of pubkey/kind/tags/content).
        if (event.id != event.computeIdHex()) return false
        val idBytes = hexToBytes(event.id)
        val pubBytes = hexToBytes(publicKeyXOnlyHex)
        val sigBytes = hexToBytes(event.sig)
        return Schnorr.verify(pubBytes, idBytes, sigBytes)
    }

    /** Hex helpers (no external dep). */
    fun hexToBytes(hex: String): ByteArray {
        require(hex.length % 2 == 0) { "hex length must be even" }
        val out = ByteArray(hex.length / 2)
        for (i in out.indices) {
            out[i] = ((Character.digit(hex[i * 2], 16) shl 4) or Character.digit(hex[i * 2 + 1], 16)).toByte()
        }
        return out
    }

    fun bytesToHex(bytes: ByteArray): String =
        bytes.joinToString("") { "%02x".format(it) }

    /** SHA-256 helper. */
    fun sha256(data: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(data)
}
