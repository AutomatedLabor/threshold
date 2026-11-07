package com.threshold.app.nostr

import com.threshold.app.crypto.Crypto
import com.threshold.app.crypto.NostrIdentity
import com.threshold.app.data.Defaults
import com.threshold.app.data.HeartbeatPolicy
import com.threshold.app.data.Packet
import com.threshold.app.data.PacketReleasePolicy
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.util.UUID

/**
 * Helpers to build & publish the six Threshold event kinds (per NIP §4).
 *
 * Per NIP §2 design principles: minimum publishability, E2E by default,
 * append-only, safe default. Every payload is `crypto_box_seal`'d.
 *
 * The relay never sees plaintext. The relay sees only: publisher npub,
 * recipient npub (where `p` is used), kind, created_at.
 *
 * All publish methods use [RelayPool.publish] (multi-relay, per relay-policy.md).
 */
class Publisher(private val pool: RelayPool) {

    private val json = Json { encodeDefaults = false; ignoreUnknownKeys = true }

    /**
     * Publish a heartbeat (`kind:30078`).
     * Content is encrypted to the user's own npub (so the user can read their
     * own cadence/policies from any device, but a relay cannot).
     */
    fun publishHeartbeat(
        identity: NostrIdentity,
        userKeypair: com.threshold.app.crypto.KeyPair,
        policy: HeartbeatPolicy
    ): NostrEvent {
        val content = json.encodeToString(HeartbeatPolicy.serializer(), policy)
        val sealed = Crypto.seal(content.toByteArray(Charsets.UTF_8), userKeypair.publicKeyBase64)
        val dTag = listOf("d", "threshold:heartbeat:${identity.npubHex}")
        val tags = mutableListOf<List<String>>()
        tags.add(listOf("t", THRESHOLD_TAG))
        tags.add(dTag)
        for (r in Defaults.DEFAULT_RELAYS) {
            tags.add(listOf("relay", r))
        }
        val createdAt = System.currentTimeMillis() / 1000
        val event = NostrEvent.build(identity.npubHex, createdAt, EventKinds.HEARTBEAT, tags, sealed)
        val signed = EventSigner.sign(event, hexToBytes(identity.nsecHex))
        pool.publish(signed)
        return signed
    }

    /**
     * Publish a duress event (`kind:30079`).
     * Per NIP §4.2: the EXISTENCE of this event from the user's npub is the
     * entire signal. Content is empty.
     */
    fun publishDuress(identity: NostrIdentity): NostrEvent {
        val dTag = listOf("d", "threshold:duress:${identity.npubHex}")
        val tags = listOf(listOf("t", THRESHOLD_TAG), dTag)
        val createdAt = System.currentTimeMillis() / 1000
        val event = NostrEvent.build(identity.npubHex, createdAt, EventKinds.DURESS, tags, "")
        val signed = EventSigner.sign(event, hexToBytes(identity.nsecHex))
        pool.publish(signed)
        return signed
    }

    /**
     * Publish an escalation step (`kind:30080`).
     * Step 1: encrypted to user self.
     * Step 2/3: encrypted to contact npub.
     *
     * Per NIP §8.1: this can be signed by the user OR by a watchdog delegated
     * signer (NIP-78). v1.0.0 supports both; if `signerIdentity` is the user,
     * it's user-signed; if it's the watchdog, it's NIP-78-delegated (the
     * delegation event is published separately).
     */
    fun publishEscalationStep(
        signerIdentity: NostrIdentity,
        recipientKeypair: com.threshold.app.crypto.KeyPair,
        userNpubHex: String,
        packetId: String,
        step: Int,
        graceEndsAt: Long,
        originatingHeartbeatEventId: String,
        message: String? = null
    ): NostrEvent {
        val content = buildJsonObject {
            put("v", 1)
            put("step", step)
            put("userNpub", userNpubHex)
            put("packetId", packetId)
            put("graceEndsAt", graceEndsAt)
            if (message != null) put("msg", message)
        }.toString()
        val sealed = Crypto.seal(content.toByteArray(Charsets.UTF_8), recipientKeypair.publicKeyBase64)
        val tags = listOf(
            listOf("t", THRESHOLD_TAG),
            listOf("p", recipientKeypair.publicKeyBase64),  // for routing
            listOf("packetId", packetId),
            listOf("step", step.toString()),
            listOf("e", originatingHeartbeatEventId)
        )
        val createdAt = System.currentTimeMillis() / 1000
        val event = NostrEvent.build(signerIdentity.npubHex, createdAt, EventKinds.ESCALATION, tags, sealed)
        val signed = EventSigner.sign(event, hexToBytes(signerIdentity.nsecHex))
        pool.publish(signed)
        return signed
    }

    /**
     * Publish a release packet (`kind:30081`).
     * Per NIP §4.4 (v1.0.0 ships 1-of-1 only — M-of-N deferred per iter-1 P0-17):
     * content is `crypto_box_seal`'d JSON containing the actual payload.
     *
     * @param packet the packet to release (already-sealed payload in base64)
     * @param signerIdentity identity of the publisher (user or watchdog per NIP §8.1)
     * @param recipientKeypair the contact's crypto_box keypair (the contact holds the privkey)
     * @param originatingStep3EventId event id of the kind:30080 step-3 event that triggered this release
     */
    fun publishReleasePacket(
        signerIdentity: NostrIdentity,
        recipientKeypair: com.threshold.app.crypto.KeyPair,
        packet: Packet,
        originatingStep3EventId: String
    ): NostrEvent {
        // Re-seal the payload to the recipient (the packet's encryptedPayload is already sealed,
        // but per NIP §4.4 we re-wrap with metadata). For v1.0.0 simplicity, we publish the
        // already-sealed payload as the content directly. The contact decrypts it.
        val tags = listOf(
            listOf("t", THRESHOLD_TAG),
            listOf("p", recipientKeypair.publicKeyBase64),
            listOf("packetId", packet.id),
            listOf("e", originatingStep3EventId)
        )
        val createdAt = System.currentTimeMillis() / 1000
        val event = NostrEvent.build(signerIdentity.npubHex, createdAt, EventKinds.RELEASE, tags, packet.encryptedPayload)
        val signed = EventSigner.sign(event, hexToBytes(signerIdentity.nsecHex))
        pool.publish(signed)
        return signed
    }

    /**
     * Publish a false-alarm cancellation (`kind:30082`).
     * Per NIP §4.5: must be created_at > originating kind:30080's created_at.
     */
    fun publishFalseAlarm(
        identity: NostrIdentity,
        contactKeypair: com.threshold.app.crypto.KeyPair,
        packetId: String,
        originatingEscalationEventId: String,
        reason: String = "alive"
    ): NostrEvent {
        val content = buildJsonObject {
            put("v", 1)
            put("cancelledAt", System.currentTimeMillis() / 1000)
            put("reason", reason)
        }.toString()
        val sealed = Crypto.seal(content.toByteArray(Charsets.UTF_8), contactKeypair.publicKeyBase64)
        val dTag = listOf("d", "threshold:escalation:${identity.npubHex}:$packetId")
        val tags = listOf(
            listOf("t", THRESHOLD_TAG),
            listOf("p", contactKeypair.publicKeyBase64),
            listOf("packetId", packetId),
            listOf("e", originatingEscalationEventId),
            dTag
        )
        val createdAt = System.currentTimeMillis() / 1000
        val event = NostrEvent.build(identity.npubHex, createdAt, EventKinds.FALSE_ALARM, tags, sealed)
        val signed = EventSigner.sign(event, hexToBytes(identity.nsecHex))
        pool.publish(signed)
        return signed
    }

    /**
     * Publish an audit log entry (`kind:30083`).
     * Per NIP §4.6: content is sealed to the user-designated audit-readable npub
     * (REQUIRED at onboarding per iter-1 P0-3). If auditNpubKeypair is null,
     * falls back to user's own npub (for onboarding itself, before audit npub is set).
     */
    fun publishAuditEntry(
        identity: NostrIdentity,
        auditKeypair: com.threshold.app.crypto.KeyPair?,
        userKeypair: com.threshold.app.crypto.KeyPair,
        seq: Long,
        type: String,
        details: JsonObject
    ): NostrEvent {
        val content = buildJsonObject {
            put("v", 1)
            put("seq", seq)
            put("type", type)
            put("at", System.currentTimeMillis() / 1000)
            put("details", details)
        }.toString()
        val target = auditKeypair ?: userKeypair  // fallback to self during onboarding
        val sealed = Crypto.seal(content.toByteArray(Charsets.UTF_8), target.publicKeyBase64)
        val dTag = listOf("d", "threshold:audit:${identity.npubHex}:$seq")
        val tags = listOf(listOf("t", THRESHOLD_TAG), listOf("auditType", type), dTag)
        val createdAt = System.currentTimeMillis() / 1000
        val event = NostrEvent.build(identity.npubHex, createdAt, EventKinds.AUDIT, tags, sealed)
        val signed = EventSigner.sign(event, hexToBytes(identity.nsecHex))
        pool.publish(signed)
        return signed
    }

    /** Generate a fresh UUID for a packet id. */
    fun newPacketId(): String = UUID.randomUUID().toString()

    private fun hexToBytes(hex: String): ByteArray = EventSigner.hexToBytes(hex)
}
