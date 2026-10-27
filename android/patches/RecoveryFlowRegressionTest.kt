package com.secureconnect.app.viewmodel

import com.secureconnect.app.data.model.Server
import com.secureconnect.app.vpn.ConnectionMode
import com.secureconnect.app.vpn.QuickConnectPolicy
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Regression scenarios for one-tap recovery decisions, not a real TUN test.
 * The real Xray restart and HTTPS integration test runs in verify-nodes.yml.
 */
class RecoveryFlowRegressionTest {
    private fun node(id: String, source: String = "public") = Server(
        id = id, country = "France", city = id, flagEmoji = "🌐",
        protocol = "VLESS", ping = 55, host = "$id.example.org",
        port = 443, source = source,
        rawLink = "vless://01234567-89ab-cdef-0123-456789abcdef@$id.example.org:443?security=tls"
    )

    @Test fun failedPrimaryDoesNotDisplaceConfirmedBackupAndRecoversAfterCooldown() {
        var now = 1_000_000L
        val ledger = ServerHealthLedger { now }
        val primary = node("primary")
        val backup = node("backup")
        ledger.recordSuccess(primary.id, 90)
        now += 1_000L
        ledger.recordSuccess(backup.id, 140)
        assertEquals("primary", ledger.rank(listOf(backup, primary)).first().id)

        ledger.recordFailure(primary.id, "tls")
        assertTrue(ledger.isCoolingDown(primary.id))
        assertEquals("backup", ledger.rank(listOf(primary, backup)).first().id)
        assertFalse(ledger.hasSuccessfulHistory(primary.id))

        now += 30_001L
        ledger.recordSuccess(primary.id, 75)
        assertFalse(ledger.isCoolingDown(primary.id))
        assertTrue(ledger.hasSuccessfulHistory(primary.id))
        assertEquals("primary", ledger.rank(listOf(primary, backup)).first().id)
    }

    @Test fun oneTapRequestWaitsForLocalProofButCannotConnectAfterUserCancel() {
        val request = AutoSelectionRequest()
        request.request()
        assertFalse(request.consumeIf(ready = false, connecting = false))
        assertTrue(request.pending.value)
        request.cancel()
        assertFalse(request.consumeIf(ready = true, connecting = false))
        assertFalse(request.pending.value)
    }

    @Test fun localVerifiedBackupOverridesFreshButUntestedCloudSuggestion() {
        val proven = node("proven", source = "safe")
        val cloud = node("cloud", source = "public")
        val selected = node("selected", source = "other")
        val ordered = QuickConnectPolicy.order(
            selected = selected, mode = ConnectionMode.AUTO,
            explicitSelection = false,
            verified = listOf(proven), historical = emptyList(),
            recentlyConnectedIds = emptyList(), catalogue = listOf(cloud),
            publicRanks = mapOf(cloud.id to 0)
        )
        assertEquals(proven.id, ordered.first().id)
        assertTrue(ordered.any { it.id == cloud.id })
    }

    @Test fun repeatedRefreshDoesNotCauseDuplicateConnectionStarts() {
        val request = AutoSelectionRequest()
        repeat(5) { request.request() }
        assertFalse(request.consumeIf(ready = true, connecting = true))
        assertTrue(request.consumeIf(ready = true, connecting = false))
        assertFalse(request.consumeIf(ready = true, connecting = false))
    }
}
