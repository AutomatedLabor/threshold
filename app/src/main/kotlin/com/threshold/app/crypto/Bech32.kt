package com.threshold.app.crypto

/**
 * Bech32 encoding/decoding (BIP-173) for npub/nsec.
 *
 * Nostr npub (public key) and nsec (private key) are bech32-encoded 32-byte
 * values, with prefixes "npub1..." and "nsec1..." respectively.
 *
 * Per NIP-19: https://github.com/nostr-protocol/nips/blob/master/19.md
 *
 * Pure Kotlin; no external dependency. Used by NostrIdentity and the
 * survivor instructions template.
 */
object Bech32 {

    private const val CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    private val CHARSET_REV = IntArray(128) { -1 }.also {
        for (i in CHARSET.indices) it[CHARSET[i].code] = i
    }

    /** Encode 32 raw bytes with the given prefix (e.g., "npub", "nsec"). Returns "prefix1...". */
    fun encode(prefix: String, data: ByteArray): String {
        // Convert from 8-bit to 5-bit groups (BIP-173).
        val converted = convertBits(data, 8, 5, true)
        val checksum = createChecksum(prefix, converted)
        val sb = StringBuilder(prefix).append('1')
        for (b in converted) sb.append(CHARSET[b.toInt() and 0x1F])
        for (b in checksum) sb.append(CHARSET[b.toInt() and 0x1F])
        return sb.toString()
    }

    /** Decode a bech32 string. Returns (prefix, data bytes). Throws on invalid format/checksum. */
    fun decode(s: String): Pair<String, ByteArray> {
        require(s.length <= 90) { "bech32 string too long" }
        require(s == s.lower() || s == s.upper) { "mixed case not allowed" }
        val str = s.lower()
        val pos = str.lastIndexOf('1')
        require(pos in 1..str.length - 7) { "no separator or too short" }
        val prefix = str.substring(0, pos)
        val charsetPart = str.substring(pos + 1)
        val data = IntArray(charsetPart.length)
        for (i in charsetPart.indices) {
            data[i] = CHARSET_REV[charsetPart[i].code]
            require(data[i] != -1) { "invalid char in data: ${charsetPart[i]}" }
        }
        verifyChecksum(prefix, data)
        val converted = convertBits(data.map { it.toByte() }.toByteArray(), 5, 8, false)
        return prefix to converted.copyOfRange(0, converted.size - 0)  // trim trailing zero-padding
    }

    private fun polymod(values: IntArray): Int {
        val GEN = intArrayOf(0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
        var chk = 1
        for (v in values) {
            val b = chk shr 25
            chk = ((chk and 0x1FFFFFF) shl 5) xor v
            for (i in 0..4) {
                if (((b shr i) and 1) == 1) chk = chk xor GEN[i]
            }
        }
        return chk
    }

    private fun expandHRP(prefix: String): IntArray {
        val out = IntArray(prefix.length * 2 + 1)
        for (i in prefix.indices) {
            out[i] = (prefix[i].code shr 5) and 0x1F
            out[i + prefix.length + 1] = prefix[i].code and 0x1F
        }
        return out
    }

    private fun verifyChecksum(prefix: String, data: IntArray) {
        val all = expandHRP(prefix) + data
        require(polymod(all) == 1) { "invalid bech32 checksum" }
    }

    private fun createChecksum(prefix: String, data: IntArray): IntArray {
        val all = expandHRP(prefix) + data + IntArray(6)
        val mod = polymod(all) xor 1
        return IntArray(6) { (mod shr (5 * (5 - it))) and 0x1F }
    }

    /** Bit conversion between 8-bit and 5-bit groups (BIP-173). */
    private fun convertBits(data: ByteArray, fromBits: Int, toBits: Int, pad: Boolean): ByteArray {
        var acc = 0
        var bits = 0
        val out = mutableListOf<Byte>()
        val maxv = (1 shl toBits) - 1
        for (b in data) {
            val value = b.toInt() and 0xFF
            require(value < (1 shl fromBits)) { "value exceeds fromBits" }
            acc = (acc shl fromBits) or value
            bits += fromBits
            while (bits >= toBits) {
                bits -= toBits
                out.add(((acc shr bits) and maxv).toByte())
            }
        }
        if (pad) {
            if (bits > 0) {
                out.add(((acc shl (toBits - bits)) and maxv).toByte())
            }
        } else {
            require(bits < fromBits) { "excess bits in convertBits" }
            require(((acc shl (toBits - bits)) and maxv) == 0) { "non-zero padding" }
        }
        return out.toByteArray()
    }
}
