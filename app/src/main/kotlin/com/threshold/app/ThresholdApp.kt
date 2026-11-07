package com.threshold.app

import android.app.Application

/**
 * Threshold application entry point.
 *
 * Initializes WorkManager scheduling (heartbeat + escalation backstops).
 *
 * The actual heartbeat publish happens in the foreground when the user taps
 * "I'm alive" (per iter-1 P0-10). The Workers are backstops for the case
 * where the user forgets to check in.
 */
class ThresholdApp : Application() {
    override fun onCreate() {
        super.onCreate()
        // Enqueue backstop workers (idempotent; uses UPDATE policy).
        com.threshold.app.work.HeartbeatWorker.enqueue(this)
        com.threshold.app.work.EscalationWorker.enqueue(this)
    }
}
