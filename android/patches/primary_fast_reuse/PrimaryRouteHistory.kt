package com.secureconnect.app.vpn

import android.content.Context
import com.secureconnect.app.data.model.Server
import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest

/**
 * Distinct from strict YouTube + double-throughput reserves:
 * memorizes an HTTPS-validated PRIMARY for a fast, secure next connection.
 *
 * Only server IDs, SHA-256 of rawLink, timestamps are persisted. Raw Xray
 * links/credentials are NEVER stored in this history. Reuse still requires a
 * fresh, certificate-validated HTTPS probe through the live Xray SOCKS.
 */
internal object PrimaryRouteHistory {
    const val FRESH_MS = 24L * 60L * 60L * 1000L
    private const val LIMIT = 12
    private const val PREFS = "sc_primary_https_proofs"
    private const val KEY = "routes_v1"

    data class Proof(val id: String, val configSha256: String, val validatedAtMs: Long)

    fun fingerprint(rawLink: String): String =
        MessageDigest.getInstance("SHA-256")
            .digest(rawLink.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }

    fun matches(proof: Proof, server: Server, nowMs: Long): Boolean =
        proof.id.isNotBlank() && proof.id == server.id &&
            server.rawLink.isNotBlank() &&
            proof.configSha256 == fingerprint(server.rawLink) &&
            proof.validatedAtMs > 0L && nowMs >= proof.validatedAtMs &&
            nowMs - proof.validatedAtMs <= FRESH_MS

    /** Local verified route priority never certifies strict speed/video quality. */
    fun eligibleIds(proofs: List<Proof>, catalogue: List<Server>, nowMs: Long): List<String> {
        val byId = catalogue.associateBy { it.id }
        return proofs.sortedByDescending { it.validatedAtMs }
            .mapNotNull { proof ->
                byId[proof.id]?.takeIf { matches(proof, it, nowMs) }?.id
            }.distinct().take(LIMIT)
    }

    fun read(context: Context): List<Proof> = runCatching {
        val json = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getString(KEY, "[]") ?: "[]"
        val arr = JSONArray(json)
        (0 until minOf(arr.length(), LIMIT * 3)).mapNotNull { i ->
            val entry = arr.optJSONObject(i) ?: return@mapNotNull null
            val id = entry.optString("id")
            val sha = entry.optString("hash")
            val time = entry.optLong("at")
            if (id.isBlank() || id.length > 180 || time <= 0 ||
                !sha.matches(Regex("^[a-f0-9]{64}$"))) null
            else Proof(id, sha, time)
        }.sortedByDescending { it.validatedAtMs }.take(LIMIT)
    }.getOrDefault(emptyList())

    fun recentIds(context: Context, catalogue: List<Server>,
                  nowMs: Long = System.currentTimeMillis()): List<String> =
        eligibleIds(read(context), catalogue, nowMs)

    fun isRecent(context: Context, server: Server,
                 nowMs: Long = System.currentTimeMillis()): Boolean =
        read(context).any { matches(it, server, nowMs) }

    fun recordValidated(context: Context, server: Server,
                        nowMs: Long = System.currentTimeMillis()) {
        if (server.id.isBlank() || server.rawLink.isBlank() || nowMs <= 0L) return
        val newest = Proof(server.id, fingerprint(server.rawLink), nowMs)
        val older = read(context).filterNot { it.id == server.id }
            .filter { nowMs >= it.validatedAtMs &&
                nowMs - it.validatedAtMs <= FRESH_MS }
        val result = JSONArray()
        (listOf(newest) + older).take(LIMIT).forEach { proof ->
            result.put(JSONObject().put("id", proof.id)
                .put("hash", proof.configSha256).put("at", proof.validatedAtMs))
        }
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putString(KEY, result.toString()).apply()
    }
}
