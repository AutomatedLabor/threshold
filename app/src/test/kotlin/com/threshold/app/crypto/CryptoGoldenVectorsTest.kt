package com.threshold.app.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Golden-vector contract tests for the crypto path (per build-contract §10 +
 * Council iter-1 P0-12). Any change to the crypto module breaks these loudly.
 *
 * The crypto_box_seal path uses an ephemeral sender, so the ciphertext is not
 * deterministic across runs. The vectors are ROUND-TRIP: open(seal(p, K), k) == p.
 * This still catches bugs in the wrapper (wrong algorithm, key handling, etc.)
 * because a round-trip failure means the encrypt/decrypt paths diverged.
 *
 * The Schnorr test vectors include the OFFICIAL BIP-340 test vector #0, which
 * has a known (privkey, message, aux, signature) and is fully deterministic.
 */
class CryptoGoldenVectorsTest {

    @Test
    fun `box_seal round-trips a known plaintext`() {
        val kp = Crypto.generateKeyPair()
        val plaintext = "Threshold version 1.0.0".toByteArray(Charsets.UTF_8)
        val cipher = Crypto.seal(plaintext, kp.publicKeyBase64)
        val plain = Crypto.open(cipher, kp.privateKeyBase64, kp.publicKeyBase64)
        assertNotNull("Crypto.open returned null — round-trip broken", plain)
        assertArrayEquals("round-trip mismatch", plaintext, plain)
    }

    @Test
    fun `box_seal round-trips empty plaintext`() {
        val kp = Crypto.generateKeyPair()
        val plaintext = ByteArray(0)
        val cipher = Crypto.seal(plaintext, kp.publicKeyBase64)
        val plain = Crypto.open(cipher, kp.privateKeyBase64, kp.publicKeyBase64)
        assertNotNull(plain)
        assertArrayEquals(plaintext, plain)
    }

    @Test
    fun `box_seal round-trips 4 KB plaintext`() {
        val kp = Crypto.generateKeyPair()
        val plaintext = ByteArray(4096) { (it and 0xFF).toByte() }
        val cipher = Crypto.seal(plaintext, kp.publicKeyBase64)
        val plain = Crypto.open(cipher, kp.privateKeyBase64, kp.publicKeyBase64)
        assertNotNull(plain)
        assertArrayEquals(plaintext, plain)
    }

    @Test
    fun `box_seal ciphertext differs for two runs (ephemeral sender)`() {
        val kp = Crypto.generateKeyPair()
        val plaintext = "same input".toByteArray(Charsets.UTF_8)
        val c1 = Crypto.seal(plaintext, kp.publicKeyBase64)
        val c2 = Crypto.seal(plaintext, kp.publicKeyBase64)
        assertTrue("crypto_box_seal must produce different ciphertexts each run (ephemeral sender)",
            c1 != c2)
    }

    @Test
    fun `box_seal open with wrong private key returns null (safe default)`() {
        val kp1 = Crypto.generateKeyPair()
        val kp2 = Crypto.generateKeyPair()
        val plaintext = "secret".toByteArray(Charsets.UTF_8)
        val cipher = Crypto.seal(plaintext, kp1.publicKeyBase64)
        // Try to open with kp2's private key (wrong key).
        val plain = Crypto.open(cipher, kp2.privateKeyBase64, kp2.publicKeyBase64)
        assertEquals("safe default: show nothing on decrypt failure", null, plain)
    }

    @Test
    fun `BIP-340 Schnorr test vector 0 - official`() {
        // From https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
        // index 0: secret_key=0x03, aux=0x00, message=0x00, signature=E907831F80848D10696A60DDF96237FE5D536876CA67F70CB8B5931FC6D39C55
        val secretKey = hexToBytes("0000000000000000000000000000000000000000000000000000000000000003")
        val auxRand = ByteArray(32)  // all zeros
        val message = ByteArray(32)  // all zeros
        val expectedSig = "E907831F80848D10696A60DDF96237FE5D536876CA67F70CB8B5931FC6D39C55".lowercase()

        val sig = Schnorr.sign(secretKey, message, auxRand)
        val sigHex = sig.joinToString("") { "%02x".format(it) }
        assertEquals("BIP-340 vector 0 signature mismatch — Schnorr impl is wrong", expectedSig, sigHex)

        // Verify against the official public key for this secret.
        val pub = Schnorr.computePublicKey(secretKey)
        val pubHex = pub.joinToString("") { "%02x".format(it) }
        assertEquals(
            "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9".lowercase(),
            pubHex
        )
        assertTrue("Schnorr.verify failed for BIP-340 vector 0", Schnorr.verify(pub, message, sig))
    }

    @Test
    fun `BIP-340 Schnorr round-trip - random keypair`() {
        val priv = Schnorr.generatePrivateKey()
        val pub = Schnorr.computePublicKey(priv)
        val message = ByteArray(32) { (it and 0xFF).toByte() }
        val sig = Schnorr.sign(priv, message)
        assertTrue("Schnorr.verify failed for random round-trip", Schnorr.verify(pub, message, sig))
    }

    @Test
    fun `BIP-340 Schnorr verification fails for tampered message`() {
        val priv = Schnorr.generatePrivateKey()
        val pub = Schnorr.computePublicKey(priv)
        val message = ByteArray(32) { (it and 0xFF).toByte() }
        val sig = Schnorr.sign(priv, message)
        // Tamper: flip one bit of the message.
        val tampered = message.copyOfRange(0, 32).also { it[0] = (it[0].toInt() xor 1).toByte() }
        assertTrue("tampered message must fail verification", !Schnorr.verify(pub, tampered, sig))
    }

    @Test
    fun `BIP-340 Schnorr verification fails for tampered signature`() {
        val priv = Schnorr.generatePrivateKey()
        val pub = Schnorr.computePublicKey(priv)
        val message = ByteArray(32) { (it and 0xFF).toByte() }
        val sig = Schnorr.sign(priv, message)
        // Tamper: flip one bit of the signature.
        val tamperedSig = sig.copyOfRange(0, 64).also { it[0] = (it[0].toInt() xor 1).toByte() }
        assertTrue("tampered signature must fail verification", !Schnorr.verify(pub, message, tamperedSig))
    }

    private fun hexToBytes(hex: String): ByteArray {
        val out = ByteArray(hex.length / 2)
        for (i in out.indices) {
            out[i] = ((Character.digit(hex[i * 2], 16) shl 4) or Character.digit(hex[i * 2 + 1], 16)).toByte()
        }
        return out
    }
}
