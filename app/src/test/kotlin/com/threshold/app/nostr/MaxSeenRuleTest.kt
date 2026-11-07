package com.threshold.app.nostr

import com.threshold.app.crypto.NostrIdentity
import com.threshold.app.data.Defaults
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Per Council iter-1 P0-4: clock-rollback defence — the survivor client
 * maintains `max-seen-created_at` as the highest `created_at` ever verified
 * for the user's npub. Any subsequent event with `created_at ≤ max-seen` is
 * invalid and ignored.
 *
 * This test exercises the max-seen rule on the SurvivorClient directly
 * (no relay pool needed) to assert the rule fires correctly.
 */
class MaxSeenRuleTest {

    @Test
    fun `events with monotonic created_at are accepted, rollback rejected`() {
        val survivor = NostrIdentity.generate()
        val user = NostrIdentity.generate()
        val client = SurvivorClient(survivor, user.npubHex, null)

        // Event 1: created_at = 1000 — accepted; max-seen becomes 1000.
        val e1 = buildEvent(user, createdAt = 1000L, kind = EventKinds.HEARTBEAT)
        assertTrue("first event must be accepted", client.onEventReceived(e1))

        // Event 2: created_at = 1500 — accepted; max-seen becomes 1500.
        val e2 = buildEvent(user, createdAt = 1500L, kind = EventKinds.HEARTBEAT)
        assertTrue("second event with higher created_at must be accepted", client.onEventReceived(e2))

        // Event 3: created_at = 1200 — REJECTED (less than max-seen of 1500).
        val e3 = buildEvent(user, createdAt = 1200L, kind = EventKinds.HEARTBEAT)
        assertTrue("rollback event must be rejected", !client.onEventReceived(e3))

        // Event 4: created_at = 1500 — REJECTED (equal to max-seen, not strictly greater).
        val e4 = buildEvent(user, createdAt = 1500L, kind = EventKinds.HEARTBEAT)
        assertTrue("equal-to-max-seen event must be rejected", !client.onEventReceived(e4))

        // Event 5: created_at = 2000 — accepted.
        val e5 = buildEvent(user, createdAt = 2000L, kind = EventKinds.HEARTBEAT)
        assertTrue("higher event must be accepted", client.onEventReceived(e5))
    }

    @Test
    fun `catch-up phase blocks escalation events until complete`() {
        val survivor = NostrIdentity.generate()
        val user = NostrIdentity.generate()
        val client = SurvivorClient(survivor, user.npubHex, null)

        // Before catch-up: escalation event must be rejected (might be stale).
        val esc1 = buildEvent(user, createdAt = 1000L, kind = EventKinds.ESCALATION)
        assertTrue("escalation during catch-up must be rejected", !client.onEventReceived(esc1))

        // Mark catch-up complete.
        client.markCatchUpComplete()

        // After catch-up: a NEWER escalation event (created_at > max-seen) is accepted.
        val esc2 = buildEvent(user, createdAt = 2000L, kind = EventKinds.ESCALATION)
        // Note: SurvivorClient.onEventReceived also requires signature verification + p-tag match.
        // Without a real contact keypair, it will pass the max-seen check but fail decryption silently.
        // For this test, we only assert the max-seen gate, not decryption.
        // (The full survivor path is exercised in SurvivorClientIntegrationTest.)
        val accepted = client.onEventReceived(esc2)
        // It will be "accepted" by the max-seen gate but produce no event emission due to keypair mismatch.
        assertTrue("escalation after catch-up must pass max-seen gate", accepted)
    }

    private fun buildEvent(identity: NostrIdentity, createdAt: Long, kind: Int): NostrEvent {
        val tags = listOf(listOf("t", THRESHOLD_TAG))
        val event = NostrEvent.build(identity.npubHex, createdAt, kind, tags, "")
        val signed = EventSigner.sign(event, EventSigner.hexToBytes(identity.nsecHex))
        return signed
    }
}
