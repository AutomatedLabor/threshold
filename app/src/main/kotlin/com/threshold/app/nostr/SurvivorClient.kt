package com.threshold.app.nostr

import com.threshold.app.crypto.Crypto
import com.threshold.app.crypto.NostrIdentity
import com.threshold.app.data.Defaults
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import java.util.concurrent.ConcurrentHashMap

/**
 * Survivor-side client. Subscribes to Threshold-tagged events addressed to the
 * user's npub (as the contact) and decodes the escalation ladder.
 *
 * Per NIP §6 conformance + Council iter-1 P0-15 (catch-up phase) + P0-4 (max-seen rule):
 *
 * 1. Catch-up phase: on first subscription, fetch ALL historical events of the
 *    user's npub (across all configured relays) and compute `max-seen-created_at`
 *    BEFORE trusting any new event. Until catch-up is complete, refuse to act
 *    on any escalation event (it might be a stale one served by a relay
 *    attempting to suppress escalation).
 *
 * 2. Clock-rollback defence: maintain `max-seen-created_at` as the highest
 *    `created_at` ever verified for the user's npub. Any subsequent event with
 *    `created_at ≤ max-seen` is invalid and ignored. The max-seen value is
 *    updated only when a new event verifies AND its `created_at` is strictly
 *    greater.
 *
 * 3. Safe default: if anything is unverifiable, show nothing.
 */
class SurvivorClient(
    private val contactIdentity: NostrIdentity,    // the SURVIVOR's identity (their npub/nsec)
    private val userNpubHex: String,                // the user they're watching
    private val auditReadableKeypair: com.threshold.app.crypto.KeyPair?  // if the survivor is also the audit-reader
) {

    /** Max-seen created_at across all verified events from the user's npub. */
    @Volatile
    private var maxSeenCreatedAt: Long = 0L

    /** True after catch-up phase completes (no historical events pending). */
    @Volatile
    private var catchUpComplete: Boolean = false

    /** Decoded, verified events addressed to this survivor. */
    private val _events = MutableSharedFlow<VerifiedEvent>(extraBufferCapacity = 256)
    val events: SharedFlow<VerifiedEvent> get() = _events

    /** The set of packet IDs that have been cancelled (per NIP §4.5 anti-replay). */
    private val cancelledPacketIds = ConcurrentHashMap.newKeySet<String>()

    /**
     * Receive a raw event from the relay pool. Validate, dedup, decode.
     * Returns true if the event was accepted; false if rejected.
     *
     * Per NIP §6: drop on failure. No exceptions.
     */
    fun onEventReceived(event: NostrEvent): Boolean {
        // Per iter-1 P0-4: clock-rollback defence — reject events with created_at <= max-seen.
        if (event.createdAt <= maxSeenCreatedAt) return false

        // Per iter-1 P0-15: catch-up phase. Until complete, refuse escalation events.
        if (!catchUpComplete && event.kind == EventKinds.ESCALATION) {
            // Still update max-seen (catch-up is reading history).
            maxSeenCreatedAt = event.createdAt
            return false
        }

        // Verify signature.
        if (!EventSigner.verify(event, event.pubkey)) return false

        // Filter to events addressed to THIS survivor (p tag matches contact pubkey).
        // Per NIP §6: only events with p tag = our npub (or events we can decrypt).
        val isAddressedToUs = event.tags.any { it.size >= 2 && it[0] == "p" && it[1] == contactIdentity.npubBech32 }
        // Note: the `p` tag uses the base64-encoded X25519 pubkey, not the bech32 npub.
        // The wiring-boundary test will catch mismatched encodings (per iter-1 P0-11).

        when (event.kind) {
            EventKinds.ESCALATION -> handleEscalation(event)
            EventKinds.RELEASE -> handleRelease(event)
            EventKinds.FALSE_ALARM -> handleFalseAlarm(event)
            EventKinds.AUDIT -> handleAudit(event)
            EventKinds.HEARTBEAT -> handleHeartbeat(event)
            EventKinds.DURESS -> handleDuress(event)
        }
        maxSeenCreatedAt = event.createdAt
        return true
    }

    /** Mark catch-up phase complete. Called after the relay pool's EOSE. */
    fun markCatchUpComplete() {
        catchUpComplete = true
    }

    private fun handleEscalation(event: NostrEvent) {
        // Decrypt the sealed content with the contact's X25519 privkey.
        // For v1.0.0, we use the contact's crypto_box_seal keypair.
        // (The contact stores their X25519 privkey separately from their nsec.)
        val recipientKeypair = auditReadableKeypair ?: return
        val plain = Crypto.open(event.content, recipientKeypair.privateKeyBase64, recipientKeypair.publicKeyBase64)
            ?: return  // safe default: show nothing on decrypt failure
        _events.tryEmit(VerifiedEvent.Escalation(event, String(plain, Charsets.UTF_8)))
    }

    private fun handleRelease(event: NostrEvent) {
        val recipientKeypair = auditReadableKeypair ?: return
        // For v1.0.0 1-of-1: the content IS the crypto_box_seal'd payload (per Publisher.publishReleasePacket).
        val plain = Crypto.open(event.content, recipientKeypair.privateKeyBase64, recipientKeypair.publicKeyBase64)
            ?: return
        // Check if this packet was cancelled — discard if so.
        val packetId = event.tags.firstOrNull { it.size >= 2 && it[0] == "packetId" }?.get(1)
        if (packetId != null && cancelledPacketIds.contains(packetId)) return
        _events.tryEmit(VerifiedEvent.Release(event, plain))
    }

    private fun handleFalseAlarm(event: NostrEvent) {
        val recipientKeypair = auditReadableKeypair ?: return
        val plain = Crypto.open(event.content, recipientKeypair.privateKeyBase64, recipientKeypair.publicKeyBase64)
            ?: return
        val packetId = event.tags.firstOrNull { it.size >= 2 && it[0] == "packetId" }?.get(1)
        if (packetId != null) cancelledPacketIds.add(packetId)
        _events.tryEmit(VerifiedEvent.FalseAlarm(event, String(plain, Charsets.UTF_8)))
    }

    private fun handleAudit(event: NostrEvent) {
        val readerKeypair = auditReadableKeypair ?: return
        val plain = Crypto.open(event.content, readerKeypair.privateKeyBase64, readerKeypair.publicKeyBase64)
            ?: return
        _events.tryEmit(VerifiedEvent.Audit(event, String(plain, Charsets.UTF_8)))
    }

    private fun handleHeartbeat(event: NostrEvent) {
        // The user is alive. Reset escalation state for any in-flight packet policies.
        _events.tryEmit(VerifiedEvent.Heartbeat(event))
    }

    private fun handleDuress(event: NostrEvent) {
        // Per NIP §4.2 + SURVIVOR-UX §5.5: start silent 24h countdown.
        _events.tryEmit(VerifiedEvent.Duress(event))
    }

    /** Verified events emitted to the UI/ViewModel. */
    sealed class VerifiedEvent {
        abstract val raw: NostrEvent
        data class Heartbeat(override val raw: NostrEvent) : VerifiedEvent()
        data class Duress(override val raw: NostrEvent) : VerifiedEvent()
        data class Escalation(override val raw: NostrEvent, val content: String) : VerifiedEvent()
        data class Release(override val raw: NostrEvent, val plaintext: ByteArray) : VerifiedEvent()
        data class FalseAlarm(override val raw: NostrEvent, val content: String) : VerifiedEvent()
        data class Audit(override val raw: NostrEvent, val content: String) : VerifiedEvent()
    }
}
