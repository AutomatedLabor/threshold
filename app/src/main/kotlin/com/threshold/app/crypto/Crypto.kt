package com.threshold.app.crypto

import com.goterl.lazysodium.LazySodiumAndroid
import com.goterl.lazysodium.SodiumAndroid
import com.goterl.lazysodium.interfaces.BoxSeal
import com.goterl.lazysodium.utils.Key
import java.util.Base64

/**
 * Crypto wrapper around libsodium (LazysodiumAndroid binding).
 *
 * Per build-contract §9: every release packet is encrypted to the contact's
 * pubkey with `crypto_box_seal`. The relay never sees plaintext.
 *
 * This class is the ONLY place in the app that calls into libsodium. All other
 * code goes through [Crypto]. This makes the crypto path a single seam that
 * the golden-vector and property-based fuzz tests can exercise.
 *
 * Memory hygiene: per build-contract §9, plaintext byte arrays are zeroed
 * with `sodium_memzero` after use via [zero]. The Kotlin GC will eventually
 * reclaim them but we don't wait for that.
 *
 * JVM-testable: uses java.util.Base64 (Android API 26+ per project minSdk),
 * not android.util.Base64 (which would require Robolectric).
 */
object Crypto {

    /** Lazily-initialized libsodium. Initialization is idempotent and thread-safe. */
    private val lazySodium: LazySodiumAndroid by lazy {
        SodiumAndroid.load()
        LazySodiumAndroid(SodiumAndroid())
    }

    /**
     * Generate a new X25519 keypair for `crypto_box_seal`.
     * Returns (privateKey 32 bytes, publicKey 32 bytes), both base64-encoded.
     */
    fun generateKeyPair(): KeyPair {
        val key = lazySodium.cryptoBoxSealGenKeyPair()
        val priv = key.secretKey.bytes
        val pub = key.publicKey.bytes
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
        val cipher = ByteArray(plaintext.size + BoxSeal.SEALBYTES)
        val ok = lazySodium.cryptoBoxSealEasy(plaintext, plaintext.size.toLong(), Key.fromBytes(recipientPub), cipher)
        zero(recipientPub)
        if (!ok) {
            zero(plaintext); zero(cipher)
            throw IllegalStateException("crypto_box_seal_easy returned false")
        }
        val out = Base64.getEncoder().encodeToString(cipher)
        zero(plaintext); zero(cipher)
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
            val plain = ByteArray(cipher.size - BoxSeal.SEALBYTES)
            val ok = lazySodium.cryptoBoxSealOpenEasy(cipher, cipher.size.toLong(), Key.fromBytes(pub), Key.fromBytes(priv), plain)
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
        val out = ByteArray(count)
        lazySodium.randomBytesBuf(out, count.toLong())
        return out
    }

    /**
     * Zero a byte array using `sodium_memzero` (per build-contract §9 memory hygiene).
     * Best-effort: clears the array in place; does not prevent earlier GC of references.
     */
    fun zero(arr: ByteArray) {
        try {
            SodiumAndroid.get().sodium_memzero(arr, arr.size.toLong())
        } catch (_: Throwable) {
            // Fallback: Kotlin-native fill(0) if JNI sodium_memzero isn't available.
            arr.fill(0)
        }
    }
}

/** X25519 keypair for crypto_box_seal. */
data class KeyPair(
    val privateKeyBase64: String,
    val publicKeyBase64: String
)
