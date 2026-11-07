package com.threshold.app.data

import com.threshold.app.crypto.Crypto
import kotlinx.serialization.Serializable

/**
 * The local-first encrypted vault. The vault is the source of truth.
 *
 * Per build-contract §2: vault lives on-device, encrypted at rest with a key
 * sealed by Android KeyStore (StrongBox if available, TEE otherwise).
 *
 * For v1.0.0 in the sandbox, the vault key is derived from the BIP-39 mnemonic
 * and the vault is stored as an encrypted blob in the app's private storage.
 *
 * Per build-contract §11: backup is mandatory (BIP-39 paper backup; the app
 * refuses to seal the first release packet until backup is confirmed).
 *
 * Per THREAT-MODEL §2 A1: vault contents (packets, contacts, schedule) are
 * the highest-value asset. Without backup: unrecoverable. By design.
 *
 * NostrIdentity and KeyPair are serialized as their String fields (nsecHex,
 * npubHex, privateKeyBase64, publicKeyBase64) for kotlinx-serialization
 * compatibility.
 */
@Serializable
data class Vault(
    val identityNsecHex: String,
    val identityNpubHex: String,
    val identityNsecBech32: String,
    val identityNpubBech32: String,
    val auditReadablePrivateKeyBase64: String,
    val auditReadablePublicKeyBase64: String,
    val userPrivateKeyBase64: String,
    val userPublicKeyBase64: String,
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
    /** Reconstruct the NostrIdentity object from the vault's string fields. */
    fun toIdentity(): com.threshold.app.crypto.NostrIdentity =
        com.threshold.app.crypto.NostrIdentity(
            nsecHex = identityNsecHex,
            npubHex = identityNpubHex,
            nsecBech32 = identityNsecBech32,
            npubBech32 = identityNpubBech32
        )

    /** Reconstruct the audit-readable keypair (used to decrypt audit log entries). */
    fun toAuditReadableKeypair(): com.threshold.app.crypto.KeyPair =
        com.threshold.app.crypto.KeyPair(
            privateKeyBase64 = auditReadablePrivateKeyBase64,
            publicKeyBase64 = auditReadablePublicKeyBase64
        )

    /** Reconstruct the user's X25519 keypair (used to seal heartbeats to self). */
    fun toUserKeypair(): com.threshold.app.crypto.KeyPair =
        com.threshold.app.crypto.KeyPair(
            privateKeyBase64 = userPrivateKeyBase64,
            publicKeyBase64 = userPublicKeyBase64
        )

    companion object {
        private val json = kotlinx.serialization.json.Json {
            encodeDefaults = true; ignoreUnknownKeys = true; prettyPrint = false
        }

        /**
         * Initialize a fresh vault during onboarding. Generates identity, audit
         * keypair, and user keypair (for crypto_box_seal to self in heartbeats).
         */
        fun initialize(): Vault {
            val identity = com.threshold.app.crypto.NostrIdentity.generate()
            val auditKp = Crypto.generateKeyPair()
            val userKp = Crypto.generateKeyPair()
            return Vault(
                identityNsecHex = identity.nsecHex,
                identityNpubHex = identity.npubHex,
                identityNsecBech32 = identity.nsecBech32,
                identityNpubBech32 = identity.npubBech32,
                auditReadablePrivateKeyBase64 = auditKp.privateKeyBase64,
                auditReadablePublicKeyBase64 = auditKp.publicKeyBase64,
                userPrivateKeyBase64 = userKp.privateKeyBase64,
                userPublicKeyBase64 = userKp.publicKeyBase64
            )
        }

        /** Serialize + encrypt the vault with the given symmetric key (used as a crypto_box_seal recipient key). */
        fun encrypt(vault: Vault, keyBase64: String): String {
            val jsonStr = json.encodeToString(serializer(), vault)
            return Crypto.seal(jsonStr.toByteArray(Charsets.UTF_8), keyBase64)
        }

        /** Decrypt + deserialize the vault. Returns null on failure (safe default). */
        fun decrypt(ciphertextBase64: String, keyBase64: String): Vault? {
            // For v1.0.0 simplicity, the vault key is a base64-encoded 32-byte symmetric key
            // used as the crypto_box_seal recipient pubkey (and privkey for decryption).
            // crypto_box_seal uses an ephemeral sender, so the same key serves both roles.
            val plain = Crypto.open(ciphertextBase64, keyBase64, keyBase64) ?: return null
            return try {
                json.decodeFromString(serializer(), String(plain, Charsets.UTF_8))
            } catch (e: Exception) {
                null
            }
        }
    }
}
