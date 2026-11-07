package com.threshold.app.wiring

import com.threshold.app.data.Defaults
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Wiring-boundary tests for the relay list (per Council iter-1 P0-11 + ops/relay-policy.md §2).
 *
 * Asserts the default relay list has exactly the 3 specified relays and that the
 * minimum relay count is 3 (per relay-policy.md §6).
 */
class RelayWiringTest {

    @Test
    fun `default relay list has exactly 3 relays`() {
        assertEquals(3, Defaults.DEFAULT_RELAYS.size)
    }

    @Test
    fun `default relays are the ones pinned in relay-policy_md`() {
        // Per ops/relay-policy.md §2 v1.0.0 default list (Council iter-1 confirmed).
        assertEquals("wss://relay.damus.io", Defaults.DEFAULT_RELAYS[0])
        assertEquals("wss://nos.lol", Defaults.DEFAULT_RELAYS[1])
        assertEquals("wss://relay.bitid.nz", Defaults.DEFAULT_RELAYS[2])
    }

    @Test
    fun `minimum relay count is 3`() {
        // Per relay-policy.md §6: app refuses to go below 3 (would degrade replication
        // below the threat-model's multi-relay mitigation threshold).
        assertEquals(3, Defaults.MIN_RELAYS)
    }

    @Test
    fun `all default relays use wss (no plaintext ws)`() {
        // Plaintext ws leaks metadata to passive network observers. All relays must be wss.
        for (r in Defaults.DEFAULT_RELAYS) {
            assertTrue("relay $r must use wss://", r.startsWith("wss://"))
        }
    }
}
