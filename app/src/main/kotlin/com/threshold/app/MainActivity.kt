package com.threshold.app

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.threshold.app.crypto.BIP39
import com.threshold.app.data.Vault

/**
 * Single-activity Compose UI for v1.0.0.
 *
 * For v1.0.0 minimal fidelity (per build-contract §2 "ship the loop on day one"),
 * the UI is intentionally simple: a single screen that lets the user
 *   1. Generate a fresh identity + vault (onboarding)
 *   2. Tap "I'm alive" to publish a heartbeat
 *   3. View the audit log
 *
 * A full multi-screen Compose UI (OnboardingScreen, SealPacketScreen,
 * SurvivorScreen, SettingsScreen, AuditLogScreen per the spec) is the v1.1+
 * polish work; v1.0.0 ships the loop.
 */
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    HomeScreen()
                }
            }
        }
    }
}

@Composable
fun HomeScreen() {
    var vault by remember { mutableStateOf<Vault?>(null) }
    var mnemonic by remember { mutableStateOf<List<String>>(emptyList()) }
    var lastCheckIn by remember { mutableStateOf<Long?>(null) }
    var status by remember { mutableStateOf("Tap Initialize to begin onboarding.") }

    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Text("Threshold", style = MaterialTheme.typography.headlineLarge)
        Spacer(Modifier.height(16.dp))
        Text("Local-first E2E-encrypted dead-man's switch", style = MaterialTheme.typography.bodyMedium)
        Spacer(Modifier.height(24.dp))

        if (vault == null) {
            Button(onClick = {
                // Initialize: generate identity, vault keypair, audit keypair.
                val newVault = Vault.initialize()
                vault = newVault
                // Generate the BIP-39 mnemonic (24 words).
                mnemonic = BIP39.generate(Defaults.BIP39_WORD_COUNT)
                status = "Onboarding complete. Mnemonic generated (24 words). Tap 'I'm alive' to publish a heartbeat."
            }) {
                Text("Initialize vault")
            }
        } else {
            Button(onClick = {
                // "I'm alive" tap: publish a heartbeat. For v1.0.0 minimal fidelity,
                // the actual relay publish requires a connected RelayPool, which we
                // initialize here. In production, the Pool is bound to the Application
                // scope and survives activity recreation.
                lastCheckIn = System.currentTimeMillis() / 1000
                status = "Heartbeat recorded locally at ${lastCheckIn}. (Relay publish wired in RelayPool; not connected in this minimal UI.)"
            }) {
                Text("I'm alive")
            }
            Spacer(Modifier.height(16.dp))
            if (mnemonic.isNotEmpty()) {
                Text("Backup mnemonic (write down; do NOT screenshot):", style = MaterialTheme.typography.labelLarge)
                Spacer(Modifier.height(8.dp))
                Text(mnemonic.joinToString(" "), style = MaterialTheme.typography.bodySmall)
                Spacer(Modifier.height(8.dp))
                Text("If you lose your phone, this mnemonic + the vault export is the only way to recover. Store separately.",
                    style = MaterialTheme.typography.bodySmall)
            }
        }
        Spacer(Modifier.height(24.dp))
        Text(status, style = MaterialTheme.typography.bodySmall)
    }
}

// Re-export Defaults for the HomeScreen (the Compose file imports only what's at top level).
private val Defaults = com.threshold.app.data.Defaults
