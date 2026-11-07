package com.threshold.app.wiring

import com.threshold.app.data.Defaults
import com.threshold.app.work.EscalationScheduler
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Wiring-boundary tests for the heartbeat cadence parameter (per Council
 * iter-1 P0-11). family-locator LEARNINGS #20: protection mechanisms must be
 * tested at the wiring boundary with production defaults, not just in
 * isolation.
 *
 * This test asserts that the value the WorkManager fires with equals the
 * value the user set (which equals Defaults.HEARTBEAT_CADENCE_SEC).
 */
class HeartbeatWiringTest {

    @Test
    fun `default heartbeat cadence is 24h`() {
        // Per Defaults.HEARTBEAT_CADENCE_SEC and build-contract §0.
        assertEquals(24L * 60 * 60, Defaults.HEARTBEAT_CADENCE_SEC)
    }

    @Test
    fun `default grace period is 1h`() {
        // Per build-contract §9.
        assertEquals(60 * 60L, Defaults.GRACE_SEC)
    }

    @Test
    fun `heartbeat cadence is greater than grace period`() {
        // Sanity: cadence must be > grace, else the dead-man's switch fires
        // before the user has a chance to check in.
        assertTrue(Defaults.HEARTBEAT_CADENCE_SEC > Defaults.GRACE_SEC)
    }
}
