package com.threshold.app.crypto

import com.goterl.lazysodium.LazySodiumAndroid
import com.goterl.lazysodium.SodiumAndroid
import com.goterl.lazysodium.interfaces.Box
import com.goterl.lazysodium.utils.Key
import java.util.Base64

/**
 * Crypto wrapper around libsodium (LazysodiumAndroid 5.1.0 binding).
 *
 * Per build-contract §9: every release packet is encrypted to the contact's
 * pubkey with `crypto_box_seal`. The relay never sees plaintext.
 *
 * Uses the low-level byte-array API (not the high-level String-based
 * `cryptoBoxSealEasy`) so the plaintext is treated as raw bytes (UTF-8,
 * PDF, image — anything). The ciphertext is base64-encoded for transport.
 *
 * JVM-testable: uses java.util.Base64 (Android API 26+ per project minSdk),
 * not android.util.Base64 (which would require Robolectric).
 *
 * Lazysodium 5.1.0 API reference (verified via javap):
 *  - LazySodiumAndroid(SodiumAndroid()) — constructor; loads native libsodium via JNA
 *  - LazySodiumAndroid.cryptoBoxKeypair() — returns lazysodium KeyPair (X25519)
 *  - LazySodiumAndroid.cryptoBoxSeal(byte[] cipher, byte[] msg, long msgLen, byte[] pub) — low-level seal
 *  - LazySodiumAndroid.cryptoBoxSealOpen(byte[] msg, byte[] cipher, long cipherLen, byte[] pub, byte[] priv) — low-level open
 *  - LazySodiumAndroid.randomBytesBuf(int) — returns ByteArray
 *  - SodiumAndroid.sodium_memzero(byte[], int) — JNA native method on the Sodium instance
 */
object Crypto {

    /** Lazily-initialized libsodium. Initialization is idempotent and thread-safe via Kotlin's `by lazy`. */
    private val lazySodium: LazySodiumAndroid by lazy {
        LazySodiumAndroid(SodiumAndroid())
    }

    /** Underlying Sodium JNA instance (for sodium_memzero). */
    private val sodium: SodiumAndroid by lazy {
        lazySodium.getSodium() as SodiumAndroid
    }

    /**
     * Generate a new X25519 keypair for `crypto_box_seal`.
     * Returns (privateKey 32 bytes, publicKey 32 bytes), both base64-encoded.
     */
    fun generateKeyPair(): KeyPair {
        val lazysodiumKp = lazySodium.cryptoBoxKeypair()
        val priv = lazysodiumKp.secretKey.asBytes
        val pub = lazysodiumKp.publicKey.asBytes
        val out = KeyPair(
            privateKeyBase64 = Base64.getEncoder().encodeToString(priv),
            publicKeyBase64 = Base64.getEncoder().encodeToString(pub)
        )
        zero(priv); zero(pub)
        return out
    }

    /**
     * Seal (anonymously encrypt) `plaintext` to `recipientPublicKeyBase64`.
     * Uses libsodium `crypto_box_seal`: anonymous sender, recipient pubkey only.
     * Returns base64 ciphertext.
     *
     * Per NIP §4.4: this is how every release packet is encrypted.
     */
    fun seal(plaintext: ByteArray, recipientPublicKeyBase64: String): String {
        val recipientPub = Base64.getDecoder().decode(recipientPublicKeyBase64)
        require(recipientPub.size == Box.PUBLICKEYBYTES) {
            "recipient public key must be ${Box.PUBLICKEYBYTES} bytes, got ${recipientPub.size}"
        }
        val cipher = ByteArray(plaintext.size + Box.SEALBYTES)
        val ok = lazySodium.cryptoBoxSeal(cipher, plaintext, plaintext.size.toLong(), recipientPub)
        zero(recipientPub)
        if (!ok) {
            zero(cipher)
            throw IllegalStateException("cryptoBoxSeal returned false")
        }
        val out = Base64.getEncoder().encodeToString(cipher)
        zero(cipher)
        return out
    }

    /**
     * Open (decrypt) a `crypto_box_seal`'d `ciphertextBase64` using `privateKeyBase64` + `publicKeyBase64`.
     * Returns the plaintext, or null on failure (the safe default per NIP §6: show nothing on decrypt failure).
     */
    fun open(ciphertextBase64: String, privateKeyBase64: String, publicKeyBase64: String): ByteArray? {
        return try {
            val cipher = Base64.getDecoder().decode(ciphertextBase64)
            val priv = Base64.getDecoder().decode(privateKeyBase64)
            val pub = Base64.getDecoder().decode(publicKeyBase64)
            require(cipher.size >= Box.SEALBYTES) { "ciphertext too short" }
            val plain = ByteArray(cipher.size - Box.SEALBYTES)
            val ok = lazySodium.cryptoBoxSealOpen(plain, cipher, cipher.size.toLong(), pub, priv)
            zero(cipher); zero(priv); zero(pub)
            if (!ok) {
                zero(plain)
                null
            } else {
                plain
            }
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Generate cryptographically-secure random bytes. Used for nonces, packet IDs, etc.
     */
    fun randomBytes(count: Int): ByteArray {
        return lazySodium.randomBytesBuf(count)
    }

    /**
     * Zero a byte array using `sodium_memzero` (per build-contract §9 memory hygiene).
     * Best-effort: clears the array in place; does not prevent earlier GC of references.
     */
    fun zero(arr: ByteArray) {
        try {
            sodium.sodium_memzero(arr, arr.size)
        } catch (_: Throwable) {
            arr.fill(0)
        }
    }
}

/**
 * X25519 keypair for crypto_box_seal, base64-encoded for transport / storage.
 * Per build-contract §9: the user generates one of these as their "audit-readable"
 * keypair and one for self-encryption of the heartbeat cadence payload.
 * Each contact's release packet is sealed to a per-contact keypair.
 */
data class KeyPair(
    val privateKeyBase64: String,
    val publicKeyBase64: String
)
