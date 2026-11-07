package com.threshold.app.crypto

import com.threshold.app.nostr.EventSigner

/**
 * Nostr identity: an nsec/npub pair, with hex forms for event signing.
 *
 * Per build-contract §9: nsec is hardware-backed via Android KeyStore when
 * available; otherwise stored encrypted in the vault. For v1.0.0, the nsec
 * is generated using [Schnorr.generatePrivateKey] and stored in the vault
 * (KeyStore-sealed at rest).
 *
 * The npub (bech32-encoded public key) is the user's Nostr identity and
 * appears as the `pubkey` field on every event the user publishes.
 */
data class NostrIdentity(
    /** 32-byte secp256k1 private key (hex string, never logged). */
    val nsecHex: String,
    /** 32-byte secp256k1 x-only public key (hex string). */
    val npubHex: String,
    /** bech32-encoded nsec ("nsec1...") for display / backup. */
    val nsecBech32: String,
    /** bech32-encoded npub ("npub1...") for display / sharing with contacts. */
    val npubBech32: String
) {
    companion object {
        /** Generate a fresh identity. Use during onboarding. */
        fun generate(): NostrIdentity {
            val priv = Schnorr.generatePrivateKey()
            val pub = Schnorr.computePublicKey(priv)
            val privHex = EventSigner.bytesToHex(priv)
            val pubHex = EventSigner.bytesToHex(pub)
            val privBech = Bech32.encode("nsec", priv)
            val pubBech = Bech32.encode("npub", pub)
            // Zero the raw priv bytes (they're now encoded).
            Crypto.zero(priv)
            return NostrIdentity(privHex, pubHex, privBech, pubBech)
        }

        /** Reconstruct an identity from a stored nsec hex. */
        fun fromNsecHex(nsecHex: String): NostrIdentity {
            val priv = EventSigner.hexToBytes(nsecHex)
            val pub = Schnorr.computePublicKey(priv)
            return NostrIdentity(
                nsecHex = nsecHex,
                npubHex = EventSigner.bytesToHex(pub),
                nsecBech32 = Bech32.encode("nsec", priv),
                npubBech32 = Bech32.encode("npub", pub)
            )
        }

        /** Reconstruct an identity from a bech32 nsec. */
        fun fromNsecBech32(nsecBech32: String): NostrIdentity {
            val (prefix, priv) = Bech32.decode(nsecBech32)
            require(prefix == "nsec") { "expected nsec prefix, got $prefix" }
            require(priv.size == 32) { "nsec must decode to 32 bytes, got ${priv.size}" }
            val privHex = EventSigner.bytesToHex(priv)
            val out = fromNsecHex(privHex)
            Crypto.zero(priv)
            return out
        }
    }
}
