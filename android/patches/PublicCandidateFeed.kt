package com.secureconnect.app.vpn

import android.content.Context
import com.secureconnect.app.data.local.ServerStore
import com.secureconnect.app.data.local.WorkingServerStore
import com.secureconnect.app.data.remote.ConfigParser
import com.secureconnect.app.data.source.ConfigSources
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.net.URL
import java.time.Instant
import javax.net.ssl.HttpsURLConnection

/**
 * Read bounded, fresh, PUBLIC share URIs from SecureConnect GitHub Pages.
 * This is NOT proof of connectivity from the phone: local Xray TLS tests still
 * gate a Connected state. Private/manual servers are never uploaded.
 */
object PublicCandidateFeed {
    private const val PAGES = "https://fowov2-jpg.github.io/Yyft/candidates.json"
    private const val RAW = "https://raw.githubusercontent.com/fowov2-jpg/Yyft/main/candidates.json"
    private const val KEY = "sc_public_candidates_v1"
    private const val MAX = 128 * 1024
    private const val TWO_HOURS = 2L * 60 * 60_000L
    private const val SKEW = 5L * 60_000L
    private val digest = Regex("[a-f0-9]{64}")
    private val protocols = setOf("vless", "vmess", "trojan", "ss")

    private fun utc(value: String): Long? = try {
        if (value.endsWith("Z")) Instant.parse(value).toEpochMilli() else null
    } catch (_: Exception) { null }

    private fun remoteHostAllowed(host: String): Boolean {
        val h = host.trim().removePrefix("[").removeSuffix("]").lowercase()
        if (h.isEmpty() || h == "localhost" || h.endsWith(".local") ||
            h.endsWith(".localhost") || h.contains(':')) return false
        if (h.matches(Regex("[0-9.]+"))) {
            val a = h.split('.').map { it.toIntOrNull() ?: return false }
            if (a.size != 4 || a.any { it !in 0..255 }) return false
            return a[0] !in setOf(0,10,127) &&
                !(a[0] == 169 && a[1] == 254) &&
                !(a[0] == 172 && a[1] in 16..31) &&
                !(a[0] == 192 && a[1] == 168) &&
                !(a[0] == 100 && a[1] in 64..127) &&
                a[0] < 224
        }
        return h.matches(Regex("[a-z0-9.-]{1,253}"))
    }

    fun recentlyVerifiedIds(context: Context): Set<String> {
        val p = context.getSharedPreferences(KEY, Context.MODE_PRIVATE)
        val at = p.getLong("success", 0L)
        val now = System.currentTimeMillis()
        return if (at > 0 && at <= now && now-at < TWO_HOURS)
            p.getStringSet("ids", emptySet()).orEmpty().toSet()
        else emptySet()
    }

    suspend fun refreshAndMerge(context: Context): Boolean = withContext(Dispatchers.IO) {
        val p = context.getSharedPreferences(KEY, Context.MODE_PRIVATE)
        val now = System.currentTimeMillis()
        val tried = p.getLong("attempted", 0L)
        if (tried > 0 && tried <= now && now - tried < 2L * 60_000L) return@withContext false
        val last = p.getLong("success", 0L)
        if (last > 0 && last <= now && now-last < 20L * 60_000L) return@withContext false
        p.edit().putLong("attempted", now).apply()
        for (endpoint in listOf(PAGES, RAW)) {
            try {
                val connection = URL(endpoint).openConnection() as HttpsURLConnection
                val bytes: ByteArray
                try {
                    connection.instanceFollowRedirects = false
                    connection.connectTimeout = 4_000
                    connection.readTimeout = 5_000
                    connection.setRequestProperty("Accept", "application/json")
                    connection.setRequestProperty("Accept-Encoding", "identity")
                    if (connection.responseCode != 200) continue
                    val sink = ByteArrayOutputStream()
                    connection.inputStream.use { input ->
                        val buf = ByteArray(4096)
                        while (true) {
                            val n = input.read(buf)
                            if (n < 0) break
                            if (sink.size() + n > MAX) throw IllegalArgumentException("too large")
                            sink.write(buf, 0, n)
                        }
                    }
                    bytes = sink.toByteArray()
                } finally { connection.disconnect() }
                val json = JSONObject(String(bytes, Charsets.UTF_8))
                val generated = utc(json.optString("generated_at")) ?: continue
                val until = utc(json.optString("valid_until")) ?: continue
                val candidates = json.optJSONArray("candidates") ?: continue
                if (json.optInt("schema", -1) != 1 ||
                    json.optString("checker") != "xray-github-actions" ||
                    generated > now+SKEW || until <= now ||
                    until < generated || until-generated > TWO_HOURS+SKEW ||
                    candidates.length() > 24) continue
                val sources = ConfigSources.all.associateBy { it.id }
                val nodes = LinkedHashMap<String, com.secureconnect.app.data.model.Server>()
                for (i in 0 until candidates.length()) {
                    val c = candidates.optJSONObject(i) ?: continue
                    val sourceId = c.optString("source_id")
                    val sourceName = PublicCandidateSourcePolicy.nameFor(
                        sourceId, sources.mapValues { it.value.name }) ?: continue
                    val uri = c.optString("uri")
                    val checked = utc(c.optString("checked_at")) ?: continue
                    val fp = c.optString("fingerprint")
                    if (uri.length !in 20..4096 || uri.contains('#') ||
                        uri.substringBefore("://").lowercase() !in protocols ||
                        !digest.matches(fp) || NodeFingerprint.of(uri) != fp ||
                        checked > now+SKEW || now-checked !in 0L until TWO_HOURS ||
                        c.opt("youtube_page_ok") !is Boolean ||
                        c.optInt("https_latency_ms", -1) !in 1..30_000) continue
                    val server = ConfigParser.parse(uri, sourceName) ?: continue
                    if (!remoteHostAllowed(server.host) ||
                        XrayConfigBuilder.build(server, null) == null) continue
                    nodes.putIfAbsent(server.id, server.copy(ping = 0))
                }
                // A nonempty publication may contain only URI formats unsupported
                // by this Android build. Try the independent Raw endpoint rather
                // than falsely recording a successful cloud import.
                if (PublicCandidateFallbackPolicy.tryAlternateEndpoint(
                        candidates.length(), nodes.size)) continue
                // A genuinely empty valid publication remains a valid result.
                p.edit().putLong("success", now)
                    .putStringSet("ids", nodes.keys.toSet()).apply()
                if (nodes.isEmpty()) return@withContext false
                // Preserve real local successes over externally suggested nodes.
                val verified = WorkingServerStore.activeRecords(context).map { it.server }
                val combined = (verified + nodes.values + ServerStore.loadCached(context))
                    .distinctBy { it.id }.take(ServerStore.MAX_CACHED_SERVERS)
                ServerStore.saveCached(context, combined)
                return@withContext true
            } catch (e: CancellationException) { throw e }
            catch (_: Exception) { /* Offline/invalid: retain existing routes. */ }
        }
        false
    }
}
