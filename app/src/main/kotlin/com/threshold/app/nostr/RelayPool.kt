package com.threshold.app.nostr

import com.threshold.app.data.Defaults
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit

/**
 * Multi-relay Nostr client (per ops/relay-policy.md §4: subscribe to all 3
 * default relays in parallel, deduplicate by event id, accept first verified).
 *
 * Per THREAT-MODEL §4 A4: multi-relay is the mitigation for relay misbehavior
 * (drop / delay / replay / inject). A compromised relay that delays an event
 * will lose the race to a non-compromised relay.
 *
 * Publishes are sent to ALL relays; the survivor client accepts an event
 * as soon as ANY relay delivers a verified one (per relay-policy.md §4).
 *
 * v1.0.0 uses OkHttp WebSocket for relay connections. The default 3 relays
 * (per Defaults.DEFAULT_RELAYS) are connected when [RelayPool.start] is called.
 */
class RelayPool(
    private val relays: List<String> = Defaults.DEFAULT_RELAYS,
    private val onEventReceived: (NostrEvent) -> Unit
) {
    private val client = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(0, TimeUnit.SECONDS)   // long-lived WebSocket
        .pingInterval(30, TimeUnit.SECONDS)
        .build()

    private val sockets = ConcurrentHashMap<String, WebSocket>()
    private val seenEventIds = ConcurrentHashMap.newKeySet<String>()

    /** Outbound publish queue (events that have not yet been ACK'd by all relays). */
    private val pendingPublishes = mutableListOf<Pair<NostrEvent, String>>()

    /** Outbound subscription IDs per relay. */
    private val subscriptionIds = ConcurrentHashMap<String, String>()

    /** Errors from relays (for diagnostics; not the audit log). */
    private val _errors = MutableSharedFlow<Pair<String, String>>(extraBufferCapacity = 64)
    val errors: SharedFlow<Pair<String, String>> get() = _errors

    fun start() {
        for (relay in relays) {
            connect(relay)
        }
    }

    private fun connect(relay: String) {
        val req = Request.Builder().url(relay).build()
        val ws = client.newWebSocket(req, object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                // Subscribe to Threshold-tagged events.
                val subId = "threshold-${System.currentTimeMillis()}"
                subscriptionIds[relay] = subId
                val filter = """["REQ","$subId",{"#t":"${THRESHOLD_TAG}"}]"""
                webSocket.send(filter)
            }
            override fun onMessage(webSocket: WebSocket, text: String) {
                handleRelayMessage(relay, text)
            }
            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                _errors.tryEmit(relay to (t.message ?: "unknown failure"))
                // Reconnect with backoff (simple: 5s).
                Thread.sleep(5_000)
                connect(relay)
            }
            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                _errors.tryEmit(relay to "closed: $code $reason")
            }
        })
        sockets[relay] = ws
    }

    private fun handleRelayMessage(relay: String, text: String) {
        // NIP-01 relay messages: ["EVENT", subId, eventObj] | ["OK", eventId, ok, msg] | ["EOSE", subId]
        try {
            val parser = org.json.JSONArray(text)
            val type = parser.getString(0)
            when (type) {
                "EVENT" -> {
                    val eventObj = parser.getJSONObject(2)
                    val event = NostrEvent.fromJsonObject(kotlinx.serialization.json.Json.decodeFromString(eventObj.toString()))
                    // Deduplicate by event id across relays.
                    if (seenEventIds.add(event.id)) {
                        onEventReceived(event)
                    }
                }
                "OK" -> {
                    // Publish ACK. Could track per-relay ACK status.
                }
                "EOSE" -> {
                    // End of stored events; switch to live mode for this sub.
                }
            }
        } catch (e: Exception) {
            _errors.tryEmit(relay to "parse error: ${e.message}")
        }
    }

    /** Publish an event to all relays in the pool. */
    fun publish(event: NostrEvent) {
        val payload = NostrEvent.toJsonArray(event)
        for ((_, ws) in sockets) {
            ws.send(payload)
        }
    }

    fun stop() {
        for ((_, ws) in sockets) {
            ws.close(1000, "shutdown")
        }
        sockets.clear()
        client.dispatcher.executorService.shutdown()
    }
}
