package com.threshold.app.crypto

import java.math.BigInteger
import java.security.MessageDigest

/**
 * Pure-Kotlin BIP-340 Schnorr signature over secp256k1.
 *
 * NIP-01 mandates BIP-340 Schnorr signatures for Nostr events. This is a
 * pure-Kotlin implementation using `BigInteger` for the EC arithmetic — no
 * native lib dependency, fully testable in JVM unit tests.
 *
 * Per build-contract §9: heartbeat signing is nsec-signed kind:30078 events.
 *
 * References:
 *  - BIP-340: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
 *  - NIP-01: https://github.com/nostr-protocol/nips/blob/master/01.md
 *
 * Performance: BigInteger affine arithmetic is slow (~50ms per sign/verify on
 * a 2-CPU box). For Threshold's use case (one sign per heartbeat = 24h, one
 * verify per received event), this is fine. For 10,000 fuzz iterations, allow
 * ~10 minutes (test runs once, not on the hot path).
 */
object Schnorr {

    // secp256k1 curve parameters.
    private val P = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
    private val N = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
    private val Gx = BigInteger("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
    private val Gy = BigInteger("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)

    /** secp256k1 generator point G. */
    private val G = ECPoint(Gx, Gy)

    /** Generate a fresh secp256k1 private key (32 bytes, uniform random in [1, n-1]). */
    fun generatePrivateKey(): ByteArray {
        val random = java.security.SecureRandom()
        var d: BigInteger
        do {
            val bytes = ByteArray(32)
            random.nextBytes(bytes)
            d = BigInteger(1, bytes)
        } while (d == BigInteger.ZERO || d >= N)
        return d.toUnsigned32Bytes()
    }

    /** Compute the x-only public key (32 bytes) for a private key (32 bytes). */
    fun computePublicKey(privateKey: ByteArray): ByteArray {
        val d = BigInteger(1, privateKey)
        require(d > BigInteger.ZERO && d < N) { "Invalid private key" }
        val pub = G.multiply(d)
        return pub.x.toUnsigned32Bytes()
    }

    /**
     * BIP-340 Schnorr sign.
     * @param privateKey 32-byte private key
     * @param message 32-byte message (typically SHA-256 of the canonical event)
     * @param auxRandomness 32-byte auxiliary randomness (use SecureRandom for production)
     * @return 64-byte signature (r || s)
     */
    fun sign(privateKey: ByteArray, message: ByteArray, auxRandomness: ByteArray = ByteArray(32).also {
        java.security.SecureRandom().nextBytes(it)
    }): ByteArray {
        require(privateKey.size == 32) { "private key must be 32 bytes" }
        require(message.size == 32) { "message must be 32 bytes" }
        require(auxRandomness.size == 32) { "aux randomness must be 32 bytes" }

        val d0 = BigInteger(1, privateKey)
        require(d0 > BigInteger.ZERO && d0 < N) { "invalid private key" }

        // P = d0 * G; if d0 > n/2, use d = n - d0 (BIP-340 key prefixing).
        val P = G.multiply(d0)
        val d = if (P.hasEvenY()) d0 else N.subtract(d0)

        // t = d XOR SHA256("BIP0340/aux" || auxRandomness)
        val auxHash = taggedHash("BIP0340/aux", auxRandomness)
        val t = BigInteger(1, d.toUnsigned32Bytes()).xor(BigInteger(1, auxHash))

        // k0 = SHA256("BIP0340/nonce" || t || P.x || m) mod n
        val nonceInput = ByteArray(32 + 32 + 32)
        System.arraycopy(t.toUnsigned32Bytes(), 0, nonceInput, 0, 32)
        System.arraycopy(P.x.toUnsigned32Bytes(), 0, nonceInput, 32, 32)
        System.arraycopy(message, 0, nonceInput, 64, 32)
        val k0Hash = taggedHash("BIP0340/nonce", nonceInput)
        var k0 = BigInteger(1, k0Hash).mod(N)
        if (k0 == BigInteger.ZERO) throw IllegalStateException("k=0; retry with new aux randomness")

        // R = k0 * G; if R has odd y, k = n - k0; else k = k0.
        val R = G.multiply(k0)
        val k = if (R.hasEvenY()) k0 else N.subtract(k0)

        // e = SHA256(R.x || P.x || m) mod n
        val challengeInput = ByteArray(32 + 32 + 32)
        System.arraycopy(R.x.toUnsigned32Bytes(), 0, challengeInput, 0, 32)
        System.arraycopy(P.x.toUnsigned32Bytes(), 0, challengeInput, 32, 32)
        System.arraycopy(message, 0, challengeInput, 64, 32)
        val e = BigInteger(1, taggedHash("BIP0340/challenge", challengeInput)).mod(N)

        // s = (k + e*d) mod n
        val s = k.add(e.multiply(d)).mod(N)

        // signature = R.x (32 bytes) || s (32 bytes)
        val sig = ByteArray(64)
        System.arraycopy(R.x.toUnsigned32Bytes(), 0, sig, 0, 32)
        System.arraycopy(s.toUnsigned32Bytes(), 0, sig, 32, 32)
        // Verify the signature before returning (BIP-340 requires this — fail-closed).
        if (!verify(P.x.toUnsigned32Bytes(), message, sig)) {
            throw IllegalStateException("self-verification failed; abort")
        }
        return sig
    }

    /**
     * BIP-340 Schnorr verify.
     * @param publicKeyXOnly 32-byte x-only public key
     * @param message 32-byte message
     * @param signature 64-byte signature (r || s)
     * @return true if the signature is valid
     */
    fun verify(publicKeyXOnly: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
        if (publicKeyXOnly.size != 32 || message.size != 32 || signature.size != 64) return false
        val r = BigInteger(1, signature.copyOfRange(0, 32))
        val s = BigInteger(1, signature.copyOfRange(32, 64))
        if (r >= P || s >= N) return false

        // Lift X to a point P (find y such that x^3 + 7 = y^2 mod p).
        val P = liftX(publicKeyXOnly) ?: return false

        // e = SHA256(r || P.x || m) mod n
        val challengeInput = ByteArray(32 + 32 + 32)
        System.arraycopy(signature, 0, challengeInput, 0, 32)  // r
        System.arraycopy(publicKeyXOnly, 0, challengeInput, 32, 32)  // P.x
        System.arraycopy(message, 0, challengeInput, 64, 32)
        val e = BigInteger(1, taggedHash("BIP0340/challenge", challengeInput)).mod(N)

        // R = s*G - e*P
        val sG = G.multiply(s)
        val eP = P.multiply(e)
        val R = sG.add(eP.negate())
        if (R.isInfinity()) return false
        // R must have even y and R.x == r
        return R.hasEvenY() && R.x == r
    }

    /** BIP-340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || data). */
    private fun taggedHash(tag: String, data: ByteArray): ByteArray {
        val tagBytes = tag.toByteArray(Charsets.UTF_8)
        val tagHash = MessageDigest.getInstance("SHA-256").digest(tagBytes)
        val md = MessageDigest.getInstance("SHA-256")
        md.update(tagHash)
        md.update(tagHash)
        md.update(data)
        return md.digest()
    }

    /** Lift an x-coordinate to a point on secp256k1 (BIP-340). Returns null if no valid y exists. */
    private fun liftX(xBytes: ByteArray): ECPoint? {
        val x = BigInteger(1, xBytes)
        if (x >= P) return null
        // c = x^3 + 7 mod p
        val c = x.modPow(BigInteger.valueOf(3), P).add(BigInteger.valueOf(7)).mod(P)
        // y = c^((p+1)/4) mod p (since p ≡ 3 mod 4)
        val exponent = P.add(BigInteger.ONE).divide(BigInteger.valueOf(4))
        val y = c.modPow(exponent, P)
        // Check y^2 == c mod p
        if (y.modPow(BigInteger.valueOf(2), P) != c) return null
        // Return the point with even y (BIP-340 convention)
        return if (y.mod(BigInteger.valueOf(2)) == BigInteger.ZERO) ECPoint(x, y) else ECPoint(x, P.subtract(y))
    }

    /**
     * secp256k1 affine point with BigInteger arithmetic.
     * Slow but correct. Used only for signing/verification (not hot path).
     */
    private data class ECPoint(val x: BigInteger, val y: BigInteger) {
        val isInfinity: Boolean get() = x == BigInteger.ZERO && y == BigInteger.ZERO

        fun add(other: ECPoint): ECPoint {
            if (isInfinity) return other
            if (other.isInfinity) return this
            if (x == other.x) {
                if (y == other.y) return multiply(BigInteger.valueOf(2))
                return INFINITY
            }
            val lambda = (other.y.subtract(y)).multiply((other.x.subtract(x)).modInverse(P)).mod(P)
            val x3 = lambda.modPow(BigInteger.valueOf(2), P).subtract(x).subtract(other.x).mod(P)
            val y3 = lambda.multiply(x.subtract(x3)).subtract(y).mod(P)
            return ECPoint(x3, y3)
        }

        fun multiply(k: BigInteger): ECPoint {
            // Double-and-add.
            if (k == BigInteger.ZERO || isInfinity) return INFINITY
            val kAbs = if (k < BigInteger.ZERO) N.add(k) else k
            var result = INFINITY
            var addend = this
            var bits = kAbs
            while (bits > BigInteger.ZERO) {
                if (bits.and(BigInteger.ONE) == BigInteger.ONE) {
                    result = result.add(addend)
                }
                addend = addend.add(addend)
                bits = bits.shiftRight(1)
            }
            return result
        }

        fun negate(): ECPoint = if (isInfinity) this else ECPoint(x, P.subtract(y))

        fun hasEvenY(): Boolean = y.mod(BigInteger.valueOf(2)) == BigInteger.ZERO
    }

    private val INFINITY = ECPoint(BigInteger.ZERO, BigInteger.ZERO)

    /** Convert a BigInteger to 32 bytes big-endian, zero-padded. */
    private fun BigInteger.toUnsigned32Bytes(): ByteArray {
        val out = ByteArray(32)
        val bytes = this.toByteArray()
        // toByteArray may include a leading zero (for positive BigInts > 2^31 bit set)
        val src = if (bytes.size > 32 && bytes[0] == 0.toByte()) bytes.copyOfRange(1, bytes.size) else bytes
        if (src.size > 32) throw IllegalStateException("value > 2^256")
        System.arraycopy(src, 0, out, 32 - src.size, src.size)
        return out
    }
}
