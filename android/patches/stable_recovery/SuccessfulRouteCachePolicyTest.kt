package com.secureconnect.app.vpn

import com.secureconnect.app.data.model.Server
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SuccessfulRouteCachePolicyTest {
    private val now = 1_800_000_000_000L
    private fun server(name: String, link: String = "vless://$name@example.net:443") =
        Server(id = name, country = "Германия", city = "Berlin", flagEmoji = "🇩🇪",
            protocol = "VLESS", ping = 40, host = "example.net", port = 443,
            rawLink = link)
    private fun entry(id: String, agoMs: Long = 1_000L,
                      failures: Int = 0, failedAgoMs: Long = 0L) =
        SuccessfulRouteCachePolicy.Entry(server(id), now - agoMs,
            if (failedAgoMs > 0) now - failedAgoMs else 0L, failures)

    @Test fun savedOnlyAfterActualSuccessAndLimitedTo12() {
        val saved = (1..20).fold(emptyList<SuccessfulRouteCachePolicy.Entry>()) { prev, n ->
            SuccessfulRouteCachePolicy.mergeSuccess(prev, server("node$n"), now + n)
        }
        assertEquals(12, saved.size)
        assertEquals("node20", saved.first().server.id)
        assertEquals(0, SuccessfulRouteCachePolicy.mergeSuccess(
            emptyList(), server(""), now).size)
    }

    @Test fun expiredRiskyAndCoolingNodesAreExcluded() {
        val saved = listOf(
            entry("fresh"), entry("expired", SuccessfulRouteCachePolicy.KEEP_MS + 1),
            entry("cooldown", failures = 1, failedAgoMs = 1_000L), entry("risky"))
        val shortlist = SuccessfulRouteCachePolicy.candidates(saved, now) {
            it.id != "risky"
        }
        assertEquals(listOf("fresh"), shortlist.map { it.id })
        assertTrue(SuccessfulRouteCachePolicy.candidates(saved, now + 16 * 60_000L) {
            it.id != "risky" }.any { it.id == "cooldown" })
    }

    @Test fun onlyThreeExactPreviouslySuccessfulConfigsPerWave() {
        val saved = (1..9).map { entry("s$it", agoMs = it * 1_000L) }
        val shortlist = SuccessfulRouteCachePolicy.candidates(saved, now) { true }
        assertEquals(3, shortlist.size)
        assertEquals(saved.take(3).map { it.server.rawLink }, shortlist.map { it.rawLink })
    }

    @Test fun changedCredentialsReplaceOldAndRestoreHealth() {
        val before = listOf(entry("s1", failures = 2, failedAgoMs = 1_000L))
        val updated = server("s1", "vless://changed-secret@example.net:443")
        val result = SuccessfulRouteCachePolicy.mergeSuccess(before, updated, now)
        assertEquals(1, result.size)
        assertEquals(updated.rawLink, result.first().server.rawLink)
        assertEquals(0, result.first().failures)
        assertEquals(0L, result.first().failedAtMs)
    }

    @Test fun failurePreservesEvidenceAndOnlyCoolsExactConfiguration() {
        val current = entry("s1")
        val wrongLink = server("s1", "vless://unrelated@example.net")
        assertEquals(listOf(current), SuccessfulRouteCachePolicy.mergeFailure(
            listOf(current), wrongLink, now))
        val failed = SuccessfulRouteCachePolicy.mergeFailure(
            listOf(current), current.server, now).single()
        assertEquals(1, failed.failures)
        assertFalse(SuccessfulRouteCachePolicy.recovering(failed, now + 60_000L))
        assertTrue(SuccessfulRouteCachePolicy.recovering(failed, now + 16 * 60_000L))
    }
}