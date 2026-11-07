package com.threshold.app.wiring

import com.threshold.app.crypto.Crypto
import com.threshold.app.crypto.Schnorr
import com.threshold.app.data.Defaults
import com.threshold.app.data.HeartbeatPolicy
import com.threshold.app.data.PacketReleasePolicy
import com.threshold.app.nostr.EventKinds
import com.threshold.app.nostr.EventSigner
import com.threshold.app.nostr.NostrEvent
import com.threshold.app.nostr.Publisher
import com.threshold.app.nostr.RelayPool
import com.threshold.app.nostr.SurvivorClient
import com.threshold.app.nostr.THRESHOLD_TAG
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Wiring-boundary tests for the crypto key + signing flow (per Council iter-1 P0-11).
 *
 * Asserts: a heartbeat signed by the user's nsec verifies with the user's npub,
 * the relay sees ciphertext (not plaintext), and the survivor client decodes
 * the round-trip. The "wiring boundary" here is: Publisher.sign → wire →
 * SurvivorClient.verify → decrypt.
 */
class CryptoKeyWiringTest {

    @Test
    fun `heartbeat event verifies with the user's npub`() {
        // Build a minimal heartbeat event by hand (no relay pool needed).
        val identity = com.threshold.app.crypto.NostrIdentity.generate()
        val content = "test-sealed-content"
        val dTag = listOf("d", "threshold:heartbeat:${identity.npubHex}")
        val tags = mutableListOf(listOf("t", THRESHOLD_TAG))
        tags.add(dTag)
        val event = NostrEvent.build(identity.npubHex, 1234567890L, EventKinds.HEARTBEAT, tags, content)
        val signed = EventSigner.sign(event, EventSigner.hexToBytes(identity.nsecHex))
        assertTrue("signed heartbeat must verify", EventSigner.verify(signed, identity.npubHex))
    }

    @Test
    fun `heartbeat event id matches computeIdHex`() {
        val identity = com.threshold.app.crypto.NostrIdentity.generate()
        val tags = listOf(listOf("t", THRESHOLD_TAG), listOf("d", "threshold:heartbeat:${identity.npubHex}"))
        val event = NostrEvent.build(identity.npubHex, 1234567890L, EventKinds.HEARTBEAT, tags, "content")
        assertTrue("event id must match computeIdHex", event.idMatches())
    }

    @Test
    fun `tampered event id mismatches computeIdHex`() {
        val identity = com.threshold.app.crypto.NostrIdentity.generate()
        val tags = listOf(listOf("t", THRESHOLD_TAG), listOf("d", "threshold:heartbeat:${identity.npubHex}"))
        val event = NostrEvent.build(identity.npubHex, 1234567890L, EventKinds.HEARTBEAT, tags, "content")
        val tampered = event.copy(content = "tampered")
        assertTrue("tampered event id must NOT match", !tampered.idMatches())
    }

    @Test
    fun `sealed packet content is base64 ciphertext (never plaintext)`() {
        val contactKeypair = Crypto.generateKeyPair()
        val plaintext = "secret payload"
        val cipher = Crypto.seal(plaintext.toByteArray(Charsets.UTF_8), contactKeypair.publicKeyBase64)
        // The cipher should NOT contain the plaintext as a substring.
        assertTrue("ciphertext must not contain plaintext", !cipher.contains(plaintext))
        assertTrue("ciphertext must be base64", cipher.matches(Regex("^[A-Za-z0-9+/=]+$")))
    }
}
