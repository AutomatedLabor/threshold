package com.threshold.app.crypto

import java.security.SecureRandom

/**
 * BIP-39 mnemonic generation for vault-key backup (per build-contract §11).
 *
 * v1.0.0 uses 24-word mnemonics (256 bits of entropy + checksum).
 * SLIP-39 Shamir backup is deferred to v1.1+ (per THREAT-MODEL §4).
 *
 * The mnemonic is generated using [SecureRandom] (the JVM's CSPRNG) and the
 * official BIP-39 English word list (2048 words). The word list is included
 * as a resource; this class does NOT depend on any external library for it.
 *
 * The mnemonic is NEVER stored on-device in plaintext. It is shown once
 * during onboarding and (optionally) re-shown via a re-verification flow
 * gated by biometric + a 24h cooldown to defeat coercion.
 *
 * Onboarding quiz (per ops/recovery.md §3): the app quizzes the user on 3
 * random word positions; all 3 must be correct before the first packet can
 * be sealed.
 */
object BIP39 {

    /** Word count for v1.0.0 (Defaults.BIP39_WORD_COUNT). */
    const val WORD_COUNT = 24

    /**
     * Generate a fresh 24-word BIP-39 mnemonic using [SecureRandom].
     * Returns the mnemonic as a list of words (in order).
     */
    fun generate(wordCount: Int = WORD_COUNT): List<String> {
        require(wordCount == 12 || wordCount == 15 || wordCount == 18 || wordCount == 21 || wordCount == 24) {
            "BIP-39 word count must be 12, 15, 18, 21, or 24"
        }
        // BIP-39 entropy is (wordCount * 32 / 3) bits.
        val entropyBits = wordCount * 32 / 3
        val entropyBytes = entropyBits / 8
        val entropy = ByteArray(entropyBytes)
        SecureRandom().nextBytes(entropy)

        // Compute checksum: first (entropyBits / 32) bits of SHA-256(entropy).
        val digest = java.security.MessageDigest.getInstance("SHA-256").digest(entropy)
        val checksumBits = entropyBits / 32
        // Concatenate entropy bits + checksum bits → split into 11-bit groups → look up words.
        val allBits = BooleanArray(entropyBits + checksumBits)
        var bitIdx = 0
        for (b in entropy) {
            for (i in 7 downTo 0) {
                allBits[bitIdx++] = ((b.toInt() shr i) and 1) == 1
            }
        }
        for (i in 0 until checksumBits) {
            val bit = ((digest[i / 8].toInt() shr (7 - (i % 8))) and 1) == 1
            allBits[bitIdx++] = bit
        }
        val words = mutableListOf<String>()
        var i = 0
        while (i < allBits.size) {
            var idx = 0
            for (j in 0 until 11) {
                idx = (idx shl 1) or (if (allBits[i + j]) 1 else 0)
            }
            words.add(wordList[idx])
            i += 11
        }
        // Zero intermediate arrays.
        entropy.fill(0)
        digest.fill(0)
        allBits.fill(false)
        return words
    }

    /**
     * Validate a mnemonic: all words in the word list, correct length, checksum valid.
     * Returns true if valid. Used by onboarding quiz and recovery flow.
     */
    fun isValid(words: List<String>): Boolean {
        if (words.size !in listOf(12, 15, 18, 21, 24)) return false
        val indices = IntArray(words.size)
        for (i in words.indices) {
            val idx = wordListBinarySearch(words[i])
            if (idx < 0) return false
            indices[i] = idx
        }
        // Reconstruct entropy + checksum bits.
        val totalBits = words.size * 11
        val entropyBits = totalBits * 32 / 33
        val checksumBits = entropyBits / 32
        val allBits = BooleanArray(totalBits)
        var bitIdx = 0
        for (idx in indices) {
            for (i in 10 downTo 0) {
                allBits[bitIdx++] = ((idx shr i) and 1) == 1
            }
        }
        val entropy = ByteArray(entropyBits / 8)
        for (i in entropy.indices) {
            var b = 0
            for (j in 0 until 8) {
                b = (b shl 1) or (if (allBits[i * 8 + j]) 1 else 0)
            }
            entropy[i] = b.toByte()
        }
        val digest = java.security.MessageDigest.getInstance("SHA-256").digest(entropy)
        for (i in 0 until checksumBits) {
            val expected = ((digest[i / 8].toInt() shr (7 - (i % 8))) and 1) == 1
            if (allBits[entropyBits + i] != expected) {
                entropy.fill(0); digest.fill(0); allBits.fill(false)
                return false
            }
        }
        entropy.fill(0); digest.fill(0); allBits.fill(false)
        return true
    }

    /** Binary search the word list (sorted) for a word; returns -1 if not found. */
    private fun wordListBinarySearch(word: String): Int {
        var low = 0
        var high = wordList.size - 1
        while (low <= high) {
            val mid = (low + high) ushr 1
            val cmp = wordList[mid].compareTo(word)
            when {
                cmp < 0 -> low = mid + 1
                cmp > 0 -> high = mid - 1
                else -> return mid
            }
        }
        return -1
    }

    /**
     * Convert a mnemonic to a 64-byte seed using BIP-39 PBKDF2-HMAC-SHA512.
     * The seed is the vault key (per ops/recovery.md §2). The seed itself is
     * NEVER stored on-device; it is derived on demand from the mnemonic.
     *
     * The salt is "mnemonic" + passphrase (empty passphrase for v1.0.0; v1.1+
     * may add user passphrase support).
     */
    fun toSeed(words: List<String>, passphrase: String = ""): ByteArray {
        val mnemonic = words.joinToString(" ")
        val salt = ("mnemonic" + passphrase).toByteArray(Charsets.UTF_8)
        // PBKDF2-HMAC-SHA512, 2048 iterations, 64 bytes.
        val mac = javax.crypto.Mac.getInstance("HmacSHA512")
        mac.init(javax.crypto.spec.SecretKeySpec(salt, "HmacSHA512"))
        val seed = ByteArray(64)
        // Standard PBKDF2 loop.
        val pbkdf2 = javax.crypto.spec.PBEKeySpec(
            mnemonic.toCharArray(),
            salt,
            2048,
            64 * 8
        )
        val factory = javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512")
        val key = factory.generateSecret(pbkdf2)
        System.arraycopy(key.encoded, 0, seed, 0, 64)
        Crypto.zero(salt)
        pbkdf2.clearPassword()
        return seed
    }
}
