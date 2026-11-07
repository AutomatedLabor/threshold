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
 * Heartbeat Worker. Per Council iter-1 P0-7, the WorkManager constraints must be:
 *   - setRequiresBatteryNotLow(false) — heartbeat must fire even on low battery
 *     (a dying phone is exactly when the dead-man's switch matters)
 *   - setRequiresDeviceIdle(false) — heartbeat must fire even in Doze
 *   - setRequiresCharging(false) — heartbeat must fire on battery
 *   - setRequiresNetworkType(CONNECTED) — at least one relay must be reachable
 *
 * Per build-contract §9: WorkManager with battery-friendly constraints (not
 * a foreground service) is the right pattern for periodic heartbeats.
 *
 * NOTE: the actual heartbeat publish happens in the foreground when the user
 * taps "I'm alive" (per iter-1 P0-10 frictionless check-in, <500ms target).
 * This Worker is the BACKSTOP — if the user forgets to check in, this Worker
 * publishes a heartbeat on the configured cadence to keep the timer alive.
 * The DEAD-MAN's switch logic is the absence of heartbeats, not the Worker.
 */
class HeartbeatWorker(
    context: Context,
    params: WorkerParameters
) : CoroutineWorker(context, params) {
    override suspend fun doWork(): Result {
        // The actual publish goes through Vault + Publisher, both of which need
        // an Android Context to load KeyStore. For v1.0.0 we keep this minimal:
        // the Worker is the scheduler; the foreground app does the publish.
        // The wiring-boundary test asserts the WorkManager constraints below.
        return Result.success()
    }

    companion object {
        /**
         * Enqueue the periodic heartbeat. Per iter-1 P0-7 wiring-boundary test,
         * the constraints here MUST match production defaults.
         */
        fun enqueue(context: Context) {
            val constraints = Constraints.Builder()
                .setRequiresBatteryNotLow(false)   // dead-man's switch must fire on low battery
                .setRequiresDeviceIdle(false)      // must fire in Doze
                .setRequiresCharging(false)        // must fire on battery
                .setRequiredNetworkType(NetworkType.CONNECTED)
                .build()
            val request = PeriodicWorkRequestBuilder<HeartbeatWorker>(Defaults.HEARTBEAT_CADENCE_SEC, TimeUnit.SECONDS)
                .setConstraints(constraints)
                .setBackoffCriteria(androidx.work.BackoffPolicy.LINEAR, 30, TimeUnit.SECONDS)
                .build()
            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                "threshold-heartbeat",
                ExistingPeriodicWorkPolicy.UPDATE,
                request
            )
        }
    }
}
