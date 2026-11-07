package com.threshold.app.data

import com.threshold.app.crypto.Crypto
import com.threshold.app.crypto.NostrIdentity
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/**
 * The local-first encrypted vault. The vault is the source of truth.
 *
 * Per build-contract §2: vault lives on-device, encrypted at rest with a key
 * sealed by Android KeyStore (StrongBox if available, TEE otherwise).
 *
 * For v1.0.0 in the sandbox (no StrongBox), the vault key is derived from the
 * BIP-39 mnemonic and the vault is stored as an encrypted blob in the app's
 * private storage. On Android, this is /data/user/0/com.threshold.app/files/vault.enc.
 *
 * Per build-contract §11: backup is mandatory (BIP-39 paper backup; the app
 * refuses to seal the first release packet until backup is confirmed).
 *
 * Per THREAT-MODEL §2 A1: vault contents (packets, contacts, schedule) are
 * the highest-value asset. Without backup: unrecoverable. By design.
 */
@Serializable
data class Vault(
    val identity: NostrIdentity,
    val auditReadableKeypair: com.threshold.app.crypto.KeyPair,
    val userKeypair: com.threshold.app.crypto.KeyPair,
    val contacts: List<Contact> = emptyList(),
    val packets: List<Packet> = emptyList(),
    val policy: HeartbeatPolicy = HeartbeatPolicy(
        cadenceSec = Defaults.HEARTBEAT_CADENCE_SEC,
        graceSec = Defaults.GRACE_SEC,
        policies = emptyList()
    ),
    val relays: List<String> = Defaults.DEFAULT_RELAYS,
    val backupConfirmed: Boolean = false,
    val auditSeq: Long = 0L
) {
    companion object {
        private val json = Json { encodeDefaults = true; ignoreUnknownKeys = true; prettyPrint = false }

        /**
         * Initialize a fresh vault during onboarding. Generates identity, audit
         * keypair, and user keypair (for crypto_box_seal to self in heartbeats).
         */
        fun initialize(): Vault {
            return Vault(
                identity = NostrIdentity.generate(),
                auditReadableKeypair = Crypto.generateKeyPair(),
                userKeypair = Crypto.generateKeyPair()
            )
        }

        /** Serialize + encrypt the vault with the given symmetric key. */
        fun encrypt(vault: Vault, key: ByteArray): String {
            val jsonStr = json.encodeToString(serializer(), vault)
            return Crypto.seal(jsonStr.toByteArray(Charsets.UTF_8),
                java.util.Base64.getEncoder().encodeToString(key))
        }

        /** Decrypt + deserialize the vault with the given symmetric key. */
        fun decrypt(ciphertextBase64: String, key: ByteArray): Vault? {
            val keyBase64 = java.util.Base64.getEncoder().encodeToString(key)
            val plain = Crypto.open(ciphertextBase64, keyBase64, keyBase64)
                ?: return null
            return json.decodeFromString(serializer(), String(plain, Charsets.UTF_8))
        }
    }
}
