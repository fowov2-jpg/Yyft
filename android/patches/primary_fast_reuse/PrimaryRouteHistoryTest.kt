package com.secureconnect.app.vpn

import com.secureconnect.app.data.model.Server
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PrimaryRouteHistoryTest {
    private fun node(
        id: String = "finland",
        raw: String = "vless://credential@example.org:443"
    ) = Server(id = id, country = "Финляндия", city = "Helsinki",
        flagEmoji = "🇫🇮", protocol = "VLESS", ping = 39,
        host = "example.org", port = 443, rawLink = raw)

    @Test fun onlyIdenticalConfigWithin24HoursCountsAsProven() {
        val now = 1_800_000_000_000L
        val s = node()
        val proof = PrimaryRouteHistory.Proof(s.id,
            PrimaryRouteHistory.fingerprint(s.rawLink), now)
        assertTrue(PrimaryRouteHistory.matches(proof, s, now + 1000L))
        assertTrue(PrimaryRouteHistory.matches(proof, s,
            now + PrimaryRouteHistory.FRESH_MS))
        assertFalse(PrimaryRouteHistory.matches(proof, s,
            now + PrimaryRouteHistory.FRESH_MS + 1L))
        assertFalse(PrimaryRouteHistory.matches(proof, s, now - 1L))
        assertFalse(PrimaryRouteHistory.matches(proof,
            node(raw = "vless://CHANGED@example.org:443"), now + 1L))
    }

    @Test fun recentRealSuccessRanksAheadOfUnknownButNeverCertifiesBackup() {
        val now = 1_800_000_000_000L
        val good = node()
        val other = node("usa", "vless://other@example.org")
        val proofs = listOf(
            PrimaryRouteHistory.Proof(other.id,
                PrimaryRouteHistory.fingerprint(other.rawLink), now - 2000L),
            PrimaryRouteHistory.Proof(good.id,
                PrimaryRouteHistory.fingerprint(good.rawLink), now)
        )
        assertEquals(listOf("finland", "usa"),
            PrimaryRouteHistory.eligibleIds(proofs, listOf(other, good), now + 1000L))
        assertEquals(listOf("finland"),
            PrimaryRouteHistory.eligibleIds(proofs,
                listOf(node("usa", "vless://replaced@example.org"), good), now + 1000L))
    }

    @Test fun credentialsNotPersistedAsPlaintextAndInvalidProofsRejected() {
        val s = node()
        val digest = PrimaryRouteHistory.fingerprint(s.rawLink)
        assertEquals(64, digest.length)
        assertFalse(digest.contains("credential"))
        assertEquals(digest, PrimaryRouteHistory.fingerprint(s.rawLink))
        assertFalse(PrimaryRouteHistory.matches(
            PrimaryRouteHistory.Proof(s.id, digest, 0L), s, 1000L))
    }
}
