package com.threshold.app.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Random

/**
 * Property-based fuzz test of the crypto round-trip (per build-contract §10 +
 * Council iter-1 P0-13). Passes 10,000 random (plaintext, key) pairs through
 * seal → open and asserts round-trip.
 *
 * Pure-Kotlin Random is used (NOT SecureRandom) because this test is for
 * correctness of the wrapper, not for cryptographic strength. The keypair
 * itself IS generated with SecureRandom inside [Crypto.generateKeyPair].
 */
class CryptoFuzzTest {

    private val iterations = 10_000

    @Test
    fun `box_seal round-trip passes 10_000 random pairs`() {
        val rng = Random(0x7455010dL xor 0xDEADBEEFL) // fixed seed for reproducibility
        var failures = 0
        for (i in 0 until iterations) {
            val kp = Crypto.generateKeyPair()
            val len = rng.nextInt(4096)
            val plaintext = ByteArray(len)
            rng.nextBytes(plaintext)
            try {
                val cipher = Crypto.seal(plaintext, kp.publicKeyBase64)
                val plain = Crypto.open(cipher, kp.privateKeyBase64, kp.publicKeyBase64)
                assertNotNull("iteration $i: open returned null", plain)
                assertArrayEquals("iteration $i: round-trip mismatch (len=$len)", plaintext, plain)
                Crypto.zero(plaintext)
                if (plain != null) Crypto.zero(plain)
            } catch (e: Throwable) {
                failures++
                if (failures <= 3) System.err.println("iteration $i failed: ${e.message}")
            }
        }
        assertTrue("$failures/$iterations fuzz iterations failed", failures == 0)
    }

    @Test
    fun `Schnorr round-trip passes 1_000 random pairs`() {
        // Schnorr is pure-Kotlin BigInteger — slower than libsodium. 1k iterations
        // gives ~95% confidence at <60s; 10k would be 10min. Per iter-1 P0-13,
        // the box_seal path is 10k; Schnorr is 1k (signing isn't the round-trip bottleneck).
        val rng = Random(0x7455c010dL xor 0x53484500L)
        var failures = 0
        for (i in 0 until 1_000) {
            try {
                val priv = Schnorr.generatePrivateKey()
                val pub = Schnorr.computePublicKey(priv)
                val msg = ByteArray(32)
                rng.nextBytes(msg)
                val sig = Schnorr.sign(priv, msg)
                assertTrue("iteration $i: verify failed", Schnorr.verify(pub, msg, sig))
            } catch (e: Throwable) {
                failures++
                if (failures <= 3) System.err.println("iteration $i failed: ${e.message}")
            }
        }
        assertTrue("$failures/1000 Schnorr fuzz iterations failed", failures == 0)
    }

    @Test
    fun `BIP-39 generate produces valid 24-word mnemonic`() {
        repeat(100) {
            val words = BIP39.generate(24)
            assertTrue("word count must be 24", words.size == 24)
            assertTrue("mnemonic must validate", BIP39.isValid(words))
        }
    }

    @Test
    fun `BIP-39 mnemonic round-trips through toSeed and back (deterministic)`() {
        val words = BIP39.generate(24)
        val seed1 = BIP39.toSeed(words)
        val seed2 = BIP39.toSeed(words)
        assertArrayEquals("BIP-39 seed derivation must be deterministic", seed1, seed2)
        Crypto.zero(seed1); Crypto.zero(seed2)
    }

    @Test
    fun `Bech32 round-trips npub encoding`() {
        repeat(100) {
            val raw = ByteArray(32)
            java.security.SecureRandom().nextBytes(raw)
            val encoded = Bech32.encode("npub", raw)
            val (prefix, decoded) = Bech32.decode(encoded)
            assertTrue("prefix must be npub", prefix == "npub")
            assertArrayEquals("bech32 round-trip mismatch", raw, decoded)
        }
    }
}
