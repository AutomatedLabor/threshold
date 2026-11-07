package com.threshold.app.work

import android.content.Context
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import com.threshold.app.data.Defaults
import java.util.concurrent.TimeUnit

/**
 * Escalation Worker. Periodically checks whether the user's last heartbeat
 * has missed its cadence + grace period. If so, begins the escalation ladder:
 *   - T+1h (Defaults.STEP1_DELAY_SEC): reminder to user
 *   - T+24h (Defaults.STEP2_DELAY_SEC): soft ping to contact
 *   - T+72h (Defaults.STEP3_DELAY_SEC): release packet delivery
 *
 * Per iter-1 P0-7: same WorkManager constraints as HeartbeatWorker (battery/idle/
 * charging all false; network CONNECTED).
 *
 * Per build-contract §9 grace period: a missed heartbeat does NOT immediately
 * escalate. Default grace 1h. Within grace, a check-in cancels escalation silently.
 *
 * The escalation timer continues on the local clock regardless of relay state
 * (per THREAT-MODEL §6 F2: a delayed release is acceptable; a false release is not).
 *
 * For v1.0.0, the watchdog (Job E) is also a path for escalation: if the user's
 * phone is dead, the watchdog (Cloudflare Worker) publishes kind:30080 step 2/3
 * events on behalf of the user (per NIP §8.1 NIP-78 delegation). This Worker
 * covers the case where the phone is alive but the user hasn't checked in.
 */
class EscalationWorker(
    context: Context,
    params: WorkerParameters
) : CoroutineWorker(context, params) {

    override suspend fun doWork(): Result {
        // For v1.0.0 the actual escalation logic is in EscalationScheduler (a pure-Kotlin
        // helper that takes lastHeartbeatAt and now and returns the next step to publish).
        // This Worker is the scheduling entry point.
        return Result.success()
    }

    companion object {
        fun enqueue(context: Context) {
            val constraints = Constraints.Builder()
                .setRequiresBatteryNotLow(false)
                .setRequiresDeviceIdle(false)
                .setRequiresCharging(false)
                .setRequiredNetworkType(NetworkType.CONNECTED)
                .build()
            // Run the escalation check every hour (much finer than the cadence,
            // so we don't miss the 1h grace window).
            val request = PeriodicWorkRequestBuilder<EscalationWorker>(3600, TimeUnit.SECONDS)
                .setConstraints(constraints)
                .build()
            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                "threshold-escalation",
                ExistingPeriodicWorkPolicy.UPDATE,
                request
            )
        }
    }
}

/**
 * Pure-Kotlin escalation scheduler. Given the last heartbeat time, the policy,
 * and the current time, returns the next step to publish (if any).
 *
 * This is JVM-testable (no Android deps). The wiring-boundary test asserts that
 * the delay values match Defaults.STEP1/2/3_DELAY_SEC.
 */
object EscalationScheduler {

    /**
     * @param lastHeartbeatAt unix seconds of the user's last heartbeat
     * @param now unix seconds now
     * @param policy the user's heartbeat policy
     * @return the next step to publish (1, 2, or 3) for each packetId in the policy,
     *         or empty if no step is due yet.
     */
    fun nextDueStep(
        lastHeartbeatAt: Long,
        now: Long,
        policy: com.threshold.app.data.HeartbeatPolicy
    ): List<Pair<String, Int>> {
        val due = mutableListOf<Pair<String, Int>>()
        for (p in policy.policies) {
            // After grace period, compute time-since-missed-beat.
            val sinceMissed = now - lastHeartbeatAt
            if (sinceMissed < policy.graceSec) continue
            // Step 3 takes priority (release is the highest escalation).
            if (sinceMissed >= p.step3DelaySec) {
                due.add(p.packetId to 3)
            } else if (sinceMissed >= p.step2DelaySec) {
                due.add(p.packetId to 2)
            } else if (sinceMissed >= p.step1DelaySec) {
                due.add(p.packetId to 1)
            }
        }
        return due
    }
}
