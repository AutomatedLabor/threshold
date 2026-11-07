package com.threshold.app.nostr

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject

/**
 * NIP-01 Nostr event, extended for Threshold's kinds 30078-30083.
 *
 * Per NIP §2 design principles: minimum publishability, E2E by default,
 * append-only, safe default, (constant-size heartbeats deferred to v1.1+).
 *
 * The `content` field is ALWAYS a `crypto_box_seal`'d ciphertext (base64) per
 * NIP §4. The plaintext never appears on the wire or in the audit log.
 *
 * Signature (NIP-01): schnorr over `sha256(serialized_canonical_event)`,
 * where the canonical event is `[0, pubkey, created_at, kind, tags, content]`
 * as a JSON array. The signer is [EventSigner].
 *
 * The canonical form is built as an explicit string (not via kotlinx.serialization)
 * to match NIP-01's exact byte layout (no whitespace, deterministic array order).
 */
@Serializable
data class NostrEvent(
    @SerialName("id") val id: String,
    @SerialName("pubkey") val pubkey: String,
    @SerialName("created_at") val createdAt: Long,
    @SerialName("kind") val kind: Int,
    @SerialName("tags") val tags: List<List<String>>,
    @SerialName("content") val content: String,
    @SerialName("sig") val sig: String
) {
    /**
     * Compute the NIP-01 canonical event-id hash.
     * Returns the hex SHA-256 of the canonical JSON array:
     *   [0, "<pubkey_hex>", <created_at>, <kind>, [["t","threshold"],...], "<content>"]
     *
     * The serialization uses RFC-8259 JSON with no extra whitespace and exact
     * array ordering. Tags are serialized as arrays of strings (content is
     * JSON-escaped).
     */
    fun computeIdHex(): String {
        val tagsJson = tags.joinToString(",", "[", "]") { tag ->
            tag.joinToString(",", "[", "]") { v -> "\"${v.jsonEscape()}\"" }
        }
        val canonical = "[0,\"$pubkey\",$createdAt,$kind,$tagsJson,\"${content.jsonEscape()}\"]"
        val sha = java.security.MessageDigest.getInstance("SHA-256")
            .digest(canonical.toByteArray(Charsets.UTF_8))
        return sha.joinToString("") { "%02x".format(it) }
    }

    /**
     * Verify that this event's `id` field matches `computeIdHex()` (NIP-01 conformance).
     * Does NOT verify the signature (use [EventSigner.verify]).
     */
    fun idMatches(): Boolean = id == computeIdHex()

    private fun String.jsonEscape(): String =
        this.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")

    companion object {
        private val json = Json { encodeDefaults = false; ignoreUnknownKeys = true }

        /**
         * Build an unsigned event from fields + tags. Caller then signs via [EventSigner.sign]
         * to fill in `id` and `sig`.
         */
        fun build(pubkeyHex: String, createdAt: Long, kind: Int, tags: List<List<String>>, content: String): NostrEvent {
            val unsigned = NostrEvent(
                id = "", pubkey = pubkeyHex, createdAt = createdAt, kind = kind,
                tags = tags, content = content, sig = ""
            )
            return unsigned.copy(id = unsigned.computeIdHex())
        }

        /**
         * Serialize to NIP-01 JSON for publishing to a relay (CLIENT EVENT message).
         */
        fun toJsonArray(event: NostrEvent): String {
            val eventJson = json.encodeToString(NostrEvent.serializer(), event)
            return "[\"EVENT\",$eventJson]"
        }

        /**
         * Deserialize from NIP-01 JSON (EVENT message from relay or storage).
         */
        fun fromJsonObject(obj: JsonObject): NostrEvent {
            return json.decodeFromJsonElement(NostrEvent.serializer(), obj)
        }
    }
}
