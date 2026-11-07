package com.threshold.app.wiring

import com.threshold.app.data.Defaults
import com.threshold.app.data.HeartbeatPolicy
import com.threshold.app.data.PacketReleasePolicy
import com.threshold.app.work.EscalationScheduler
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Wiring-boundary tests for the escalation step delays (per Council iter-1
 * P0-11). Asserts the escalation ladder uses Defaults.STEP1/2/3_DELAY_SEC.
 *
 * Per build-contract §9 grace: T+1h reminder, T+24h soft ping, T+72h release.
 */
class EscalationWiringTest {

    @Test
    fun `escalation step 1 (reminder to user) is T+1h`() {
        assertEquals(60 * 60L, Defaults.STEP1_DELAY_SEC)
    }

    @Test
    fun `escalation step 2 (soft ping to contact) is T+24h`() {
        assertEquals(24L * 60 * 60, Defaults.STEP2_DELAY_SEC)
    }

    @Test
    fun `escalation step 3 (release delivery) is T+72h`() {
        assertEquals(72L * 60 * 60, Defaults.STEP3_DELAY_SEC)
    }

    @Test
    fun `per-packet release delay range is 24h to 168h`() {
        // Per iter-1 P0-22: 72h default, per-packet 24-168h.
        assertEquals(24L * 60 * 60, Defaults.RELEASE_DELAY_MIN_SEC)
        assertEquals(168L * 60 * 60, Defaults.RELEASE_DELAY_MAX_SEC)
        assertEquals(72L * 60 * 60, Defaults.RELEASE_DELAY_DEFAULT_SEC)
        assertTrue("max must be >= min", Defaults.RELEASE_DELAY_MAX_SEC >= Defaults.RELEASE_DELAY_MIN_SEC)
        assertTrue("default must be in [min, max]",
            Defaults.RELEASE_DELAY_DEFAULT_SEC in Defaults.RELEASE_DELAY_MIN_SEC..Defaults.RELEASE_DELAY_MAX_SEC)
    }

    @Test
    fun `EscalationScheduler fires step 1 at T+1h+grace`() {
        val policy = HeartbeatPolicy(
            cadenceSec = Defaults.HEARTBEAT_CADENCE_SEC,
            graceSec = Defaults.GRACE_SEC,
            policies = listOf(PacketReleasePolicy("p1", Defaults.STEP1_DELAY_SEC, Defaults.STEP2_DELAY_SEC, Defaults.STEP3_DELAY_SEC))
        )
        val now = 1_000_000L
        val lastHeartbeat = now - (Defaults.STEP1_DELAY_SEC + Defaults.GRACE_SEC + 1)
        val due = EscalationScheduler.nextDueStep(lastHeartbeat, now, policy)
        assertTrue("step 1 must be due", due.contains("p1" to 1))
        assertTrue("step 2 must NOT be due yet", !due.contains("p1" to 2))
        assertTrue("step 3 must NOT be due yet", !due.contains("p1" to 3))
    }

    @Test
    fun `EscalationScheduler fires step 3 at T+72h+grace`() {
        val policy = HeartbeatPolicy(
            cadenceSec = Defaults.HEARTBEAT_CADENCE_SEC,
            graceSec = Defaults.GRACE_SEC,
            policies = listOf(PacketReleasePolicy("p1", Defaults.STEP1_DELAY_SEC, Defaults.STEP2_DELAY_SEC, Defaults.STEP3_DELAY_SEC))
        )
        val now = 1_000_000L
        val lastHeartbeat = now - (Defaults.STEP3_DELAY_SEC + Defaults.GRACE_SEC + 1)
        val due = EscalationScheduler.nextDueStep(lastHeartbeat, now, policy)
        // Step 3 takes priority (release is highest escalation).
        assertTrue("step 3 must be due", due.contains("p1" to 3))
    }

    @Test
    fun `EscalationScheduler does not fire within grace period`() {
        val policy = HeartbeatPolicy(
            cadenceSec = Defaults.HEARTBEAT_CADENCE_SEC,
            graceSec = Defaults.GRACE_SEC,
            policies = listOf(PacketReleasePolicy("p1", Defaults.STEP1_DELAY_SEC, Defaults.STEP2_DELAY_SEC, Defaults.STEP3_DELAY_SEC))
        )
        val now = 1_000_000L
        val lastHeartbeat = now - (Defaults.GRACE_SEC - 10)  // within grace
        val due = EscalationScheduler.nextDueStep(lastHeartbeat, now, policy)
        assertTrue("nothing must be due within grace", due.isEmpty())
    }
}
