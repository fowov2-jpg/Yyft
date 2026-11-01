package com.secureconnect.app.vpn

import com.secureconnect.app.data.model.Server

/** Local HTTPS-verified Xray route evidence is not proof of a live spare tunnel. */
internal object SuccessfulRouteCachePolicy {
    const val MAX_SAVED = 12
    const val MAX_FALLBACK_ATTEMPTS = 3
    const val KEEP_MS = 30L * 24 * 60 * 60 * 1000
    const val FAILURE_COOLDOWN_MS = 15L * 60 * 1000

    data class Entry(
        val server: Server,
        val httpsVerifiedAtMs: Long,
        val failedAtMs: Long = 0,
        val failures: Int = 0
    )

    fun fresh(entry: Entry, nowMs: Long): Boolean =
        entry.httpsVerifiedAtMs > 0L && nowMs >= entry.httpsVerifiedAtMs &&
            nowMs - entry.httpsVerifiedAtMs <= KEEP_MS

    fun recovering(entry: Entry, nowMs: Long): Boolean =
        fresh(entry, nowMs) &&
            (entry.failedAtMs <= 0 || nowMs < entry.failedAtMs ||
                nowMs - entry.failedAtMs >= FAILURE_COOLDOWN_MS)

    /** Only schedule one protected config. Connected requires new live TLS+HTTPS. */
    fun candidates(
        entries: List<Entry>,
        nowMs: Long,
        eligible: (Server) -> Boolean
    ): List<Server> = entries.asSequence()
        .filter { recovering(it, nowMs) }
        .filter { it.server.id.isNotBlank() && it.server.rawLink.isNotBlank() }
        .filter { eligible(it.server) }
        .sortedWith(compareBy<Entry> { it.failures }
            .thenByDescending { it.httpsVerifiedAtMs })
        .distinctBy { it.server.rawLink }
        .map { it.server }
        .take(MAX_FALLBACK_ATTEMPTS)
        .toList()

    fun mergeSuccess(entries: List<Entry>, server: Server, nowMs: Long): List<Entry> {
        if (nowMs <= 0 || server.id.isBlank() || server.rawLink.isBlank()) return entries
        val freshPrior = entries.filter { fresh(it, nowMs) &&
            it.server.id != server.id && it.server.rawLink != server.rawLink }
        return (listOf(Entry(server, nowMs)) + freshPrior)
            .sortedByDescending { it.httpsVerifiedAtMs }.take(MAX_SAVED)
    }

    fun mergeFailure(entries: List<Entry>, server: Server, nowMs: Long): List<Entry> =
        entries.map { entry ->
            if (entry.server.id == server.id && entry.server.rawLink == server.rawLink &&
                nowMs > 0 && nowMs >= entry.httpsVerifiedAtMs)
                entry.copy(failedAtMs = nowMs, failures = (entry.failures + 1).coerceAtMost(99))
            else entry
        }
}