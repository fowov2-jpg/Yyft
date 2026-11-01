package com.secureconnect.app.data.local

import android.content.Context
import com.secureconnect.app.data.model.Server
import com.secureconnect.app.vpn.SuccessfulRouteCachePolicy
import org.json.JSONArray
import org.json.JSONObject

/**
 * Successful outbounds remain encrypted by Android Keystore AES-GCM.
 * Cache never leaves device, and is never sufficient to claim live Connected.
 */
internal object SuccessfulRouteCache {
    private const val PREFS = "sc_successful_routes"
    private const val KEY = "verified_fallbacks_v1"
    private val lock = Any()

    fun records(context: Context): List<SuccessfulRouteCachePolicy.Entry> = synchronized(lock) {
        read(context)
    }

    fun candidates(
        context: Context,
        nowMs: Long = System.currentTimeMillis(),
        eligible: (Server) -> Boolean
    ): List<Server> = SuccessfulRouteCachePolicy.candidates(records(context), nowMs, eligible)

    fun recordHttpsSuccess(
        context: Context, server: Server,
        nowMs: Long = System.currentTimeMillis()
    ) = synchronized(lock) {
        save(context, SuccessfulRouteCachePolicy.mergeSuccess(read(context), server, nowMs))
    }

    fun recordFailure(
        context: Context, server: Server,
        nowMs: Long = System.currentTimeMillis()
    ) = synchronized(lock) {
        val current = read(context)
        val updated = SuccessfulRouteCachePolicy.mergeFailure(current, server, nowMs)
        if (current != updated) save(context, updated)
    }

    private fun read(context: Context): List<SuccessfulRouteCachePolicy.Entry> = runCatching {
        val raw = SensitivePrefs.read(context, PREFS, KEY) ?: return@runCatching emptyList()
        val arr = JSONArray(raw)
        (0 until minOf(arr.length(), SuccessfulRouteCachePolicy.MAX_SAVED)).mapNotNull { i ->
            val row = arr.optJSONObject(i) ?: return@mapNotNull null
            val data = row.optJSONArray("config") ?: return@mapNotNull null
            val server = ServerStore.decodeServers(data).firstOrNull()
                ?: return@mapNotNull null
            val at = row.optLong("verifiedAt")
            if (at <= 0L) return@mapNotNull null
            SuccessfulRouteCachePolicy.Entry(
                server, at, row.optLong("failedAt").coerceAtLeast(0L),
                row.optInt("failures").coerceIn(0, 99))
        }
    }.getOrDefault(emptyList())

    private fun save(context: Context, records: List<SuccessfulRouteCachePolicy.Entry>) {
        val arr = JSONArray()
        records.take(SuccessfulRouteCachePolicy.MAX_SAVED).forEach { e ->
            arr.put(JSONObject()
                .put("config", JSONArray(ServerStore.encodeServers(listOf(e.server), 1)))
                .put("verifiedAt", e.httpsVerifiedAtMs)
                .put("failedAt", e.failedAtMs)
                .put("failures", e.failures))
        }
        // Fails closed if Keystore cannot decrypt previous records. No cleartext
        // fallback or replacement of an unreadable encrypted vault.
        SensitivePrefs.write(context, PREFS, KEY, arr.toString())
    }
}