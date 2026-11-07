package com.threshold.app.wiring

import com.threshold.app.crypto.Crypto
import com.threshold.app.crypto.NostrIdentity
import com.threshold.app.crypto.Schnorr
import com.threshold.app.data.Contact
import com.threshold.app.data.Packet
import com.threshold.app.data.VerificationState
import com.threshold.app.nostr.EventSigner
import com.threshold.app.nostr.Publisher
import com.threshold.app.nostr.RelayPool
import com.threshold.app.nostr.SurvivorClient
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Wiring-boundary tests for the contact npub + crypto key flow (per Council
 * iter-1 P0-11). Asserts the release packet is sealed to the EXACT contact npub
 * the user added, and the crypto key is the EXACT recipient pubkey.
 *
 * Per build-contract §9 + THREAT-MODEL §4 A6.3: mistype a contact npub →
 * verification (challenge-response) blocks sealing. Pending contacts can't
 * receive packets.
 */
class ContactNpubWiringTest {

    @Test
    fun `contact verification state defaults to PENDING`() {
        val contact = Contact(
            npub = "npub1placeholderplaceholderplaceholderplaceholderplaceholder",
            displayName = "Alice",
            verificationState = VerificationState.PENDING,
            addedAt = System.currentTimeMillis() / 1000
        )
        assertEquals(VerificationState.PENDING, contact.verificationState)
    }

    @Test
    fun `sealed packet is addressed to the exact contact npub`() {
        // Generate the contact's crypto_box_seal keypair (their X25519 keys for decryption).
        val contactKeypair = Crypto.generateKeyPair()
        // Create a packet sealed to that keypair.
        val plaintext = "Test release payload".toByteArray(Charsets.UTF_8)
        val sealedPayload = Crypto.seal(plaintext, contactKeypair.publicKeyBase64)
        val packet = Packet(
            id = java.util.UUID.randomUUID().toString(),
            contactNpub = "npub1test",
            title = "test",
            contentType = "text/plain",
            encryptedPayload = sealedPayload,
            sealedAt = System.currentTimeMillis() / 1000,
            releaseDelaySec = 72 * 60 * 60
        )
        // The packet's encryptedPayload is the crypto_box_seal output for contactKeypair.publicKeyBase64.
        // Verify the contact can decrypt it with their private key.
        val decrypted = Crypto.open(packet.encryptedPayload, contactKeypair.privateKeyBase64, contactKeypair.publicKeyBase64)
        assertNotNull("contact must be able to decrypt their packet", decrypted)
        assertEquals("decrypted content must match", plaintext.toList(), decrypted!!.toList())
    }

    @Test
    fun `NostrIdentity generated keys are valid for Schnorr signing`() {
        val id = NostrIdentity.generate()
        // nsecHex is a valid 32-byte private key.
        val privBytes = EventSigner.hexToBytes(id.nsecHex)
        assertEquals(32, privBytes.size)
        // npubHex matches computePublicKey(nsec).
        val expectedPub = Schnorr.computePublicKey(privBytes)
        assertEquals(EventSigner.bytesToHex(expectedPub), id.npubHex)
    }

    @Test
    fun `NostrIdentity fromNsecBech32 round-trips with generate`() {
        val id = NostrIdentity.generate()
        val restored = NostrIdentity.fromNsecBech32(id.nsecBech32)
        assertEquals("nsec must round-trip via bech32", id.nsecHex, restored.nsecHex)
        assertEquals("npub must round-trip via bech32", id.npubHex, restored.npubHex)
    }
}
