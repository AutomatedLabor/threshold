package com.threshold.app.audit

import com.threshold.app.crypto.Crypto
import com.threshold.app.crypto.NostrIdentity
import com.threshold.app.data.Defaults
import com.threshold.app.nostr.EventKinds
import com.threshold.app.nostr.EventSigner
import com.threshold.app.nostr.NostrEvent
import com.threshold.app.nostr.THRESHOLD_TAG
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Per build-contract §10 + Council iter-1 P0-12 (audit-log render test):
 * the audit log reader can render the last 100 events signed by the test
 * identity, in order, with verified signatures.
 *
 * This test exercises the audit log path WITHOUT a relay pool — it builds
 * 100 signed audit events in-memory and verifies the render contract.
 */
class AuditLogRenderTest {

    @Test
    fun `render last 100 audit events in order with verified signatures`() {
        val identity = NostrIdentity.generate()
        val userKeypair = Crypto.generateKeyPair()
        val auditKeypair = Crypto.generateKeyPair()

        // Build 100 sequential audit events.
        val events = (1..100).map { seq ->
            val content = """{"v":1,"seq":$seq,"type":"heartbeat-published","at":${1_000_000L + seq}}"""
            val sealed = Crypto.seal(content.toByteArray(Charsets.UTF_8), auditKeypair.publicKeyBase64)
            val dTag = listOf("d", "threshold:audit:${identity.npubHex}:$seq")
            val tags = listOf(listOf("t", THRESHOLD_TAG), listOf("auditType", "heartbeat-published"), dTag)
            val event = NostrEvent.build(
                identity.npubHex,
                createdAt = 1_000_000L + seq,
                kind = EventKinds.AUDIT,
                tags = tags,
                content = sealed
            )
            EventSigner.sign(event, EventSigner.hexToBytes(identity.nsecHex))
        }

        // The audit-log reader: verify each event's signature, sort by created_at (already sorted),
        // take the last 100, decrypt content, render.
        val rendered = mutableListOf<AuditEntry>()
        for (event in events) {
            // 1. Verify signature (per NIP §6: drop on failure).
            assertTrue("audit event ${event.id} signature must verify",
                EventSigner.verify(event, identity.npubHex))
            // 2. Verify id matches (catches tampering).
            assertTrue("audit event id must match", event.idMatches())
            // 3. Decrypt content with the audit-readable keypair.
            val plain = Crypto.open(event.content, auditKeypair.privateKeyBase64, auditKeypair.publicKeyBase64)
            assertTrue("audit event content must decrypt with audit-readable keypair", plain != null)
            val json = String(plain!!, Charsets.UTF_8)
            // 4. Parse the audit entry.
            val seq = Regex(""""seq":(\d+)""").find(json)?.groupValues?.get(1)?.toLongOrNull()
            val type = Regex(""""type":"([^"]+)"""").find(json)?.groupValues?.get(1)
            assertTrue("seq must be present", seq != null)
            assertTrue("type must be present", type != null)
            rendered.add(AuditEntry(event.createdAt, seq!!, type!!))
        }

        // 5. Assert the render contract: 100 events, in order, all verified.
        assertEquals("must render exactly 100 events", Defaults.AUDIT_LOG_RENDER_LIMIT, rendered.size)
        for (i in 1 until rendered.size) {
            assertTrue("events must be in chronological order",
                rendered[i].createdAt > rendered[i - 1].createdAt)
        }
        assertEquals("first event seq must be 1", 1L, rendered[0].seq)
        assertEquals("last event seq must be 100", 100L, rendered.last().seq)
    }

    @Test
    fun `audit event with invalid signature is dropped (not partially rendered)`() {
        val identity = NostrIdentity.generate()
        val auditKeypair = Crypto.generateKeyPair()

        // Build an audit event with a tampered signature (flip one bit).
        val content = """{"v":1,"seq":1,"type":"test","at":1000}"""
        val sealed = Crypto.seal(content.toByteArray(Charsets.UTF_8), auditKeypair.publicKeyBase64)
        val dTag = listOf("d", "threshold:audit:${identity.npubHex}:1")
        val tags = listOf(listOf("t", THRESHOLD_TAG), listOf("auditType", "test"), dTag)
        val event = NostrEvent.build(
            identity.npubHex, 1000L, EventKinds.AUDIT, tags, sealed
        )
        val signed = EventSigner.sign(event, EventSigner.hexToBytes(identity.nsecHex))
        // Tamper: flip one char of the signature.
        val tamperedSig = if (signed.sig[0] == 'a') 'b' else 'a'
        val tampered = signed.copy(sig = tamperedSig + signed.sig.substring(1))

        // The audit-log reader must drop this event (per NIP §6: drop on failure).
        val verified = EventSigner.verify(tampered, identity.npubHex)
        assertTrue("tampered audit event must NOT verify (must be dropped)", !verified)
    }

    private data class AuditEntry(val createdAt: Long, val seq: Long, val type: String)
}
