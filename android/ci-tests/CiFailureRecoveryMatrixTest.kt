package com.secureconnect.app.vpn

import com.secureconnect.app.data.model.Server
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Deterministic failure injection, WITHOUT claiming a real Android TUN connection.
 * GitHub already performs separate live Xray/SOCKS/TLS and process-restart checks.
 */
class CiFailureRecoveryMatrixTest {
    private fun node(id: String, source: String): Server = Server(
        id = id, country = "Germany", city = "Berlin", flagEmoji = "🇩🇪",
        protocol = "VLESS", ping = 40, host = "198.51.100.17", port = 443,
        source = source, rawLink = "vless://example"
    )

    @Test fun failedTlsSamplesNeedHysteresisButLostLocalXrayDoesNot() {
        assertEquals(1, GuardianPolicy.requiredFailureSamples("socks_ready", true))
        assertEquals(1, GuardianPolicy.requiredFailureSamples("socks_ready", false))
        assertEquals(3, GuardianPolicy.requiredFailureSamples("tls", true))
        assertEquals(2, GuardianPolicy.requiredFailureSamples("tls", false))
        assertEquals(3, GuardianPolicy.requiredFailureSamples("https", true))
    }

    @Test fun underlayLossBacksOffWithoutDisablingRecovery() {
        for (attempt in 1..8) {
            assertEquals(60_000L, GuardianPolicy.recoveryRetryDelayMs(attempt, false))
        }
        assertEquals(5_000L, GuardianPolicy.recoveryRetryDelayMs(1, true))
        assertEquals(10_000L, GuardianPolicy.recoveryRetryDelayMs(2, true))
        assertEquals(20_000L, GuardianPolicy.recoveryRetryDelayMs(3, true))
        assertEquals(40_000L, GuardianPolicy.recoveryRetryDelayMs(4, true))
        assertEquals(60_000L, GuardianPolicy.recoveryRetryDelayMs(7, true))
    }

    @Test fun freshMobileTlsGetsFiniteBootstrapBudget() {
        assertEquals(5_000, GuardianPolicy.initialConnectIoTimeoutMs(null))
        assertTrue(GuardianPolicy.watchdogIoTimeoutMs(2_700.0) >= 4_000)
        assertTrue(GuardianPolicy.watchdogIoTimeoutMs(20_000.0) <= 6_000)
        assertFalse(GuardianPolicy.isPoorQualitySample(45, 5_000, 2_800.0))
        assertTrue(GuardianPolicy.isPoorQualitySample(200, 3_000, 2_800.0))
    }

    @Test fun localProofBeatsCloudAndCoolingFailedRoutesMoveLast() {
        val local = node("local", "trusted")
        val cloud = node("cloud", "cloud")
        val failed = node("failed", "unstable")
        val order = QuickConnectPolicy.order(
            selected = failed, mode = ConnectionMode.AUTO, explicitSelection = false,
            verified = listOf(local), historical = emptyList(),
            recentlyConnectedIds = emptyList(), catalogue = listOf(cloud, failed),
            publicRanks = mapOf("cloud" to 0, "failed" to 1),
            isCoolingDown = { it.id == "failed" }
        )
        assertEquals("local", order.first().id)
        assertTrue(order.indexOfFirst { it.id == "cloud" } < order.indexOfFirst { it.id == "failed" })
        assertEquals("failed", order.last().id)
    }

    @Test fun cloudOnlyIsNeverPromotedIntoStrictReserve() {
        assertFalse(FastFailoverPolicy.canUseReadyReserve(false, false, false, true))
        assertFalse(FastFailoverPolicy.canUseReadyReserve(true, true, false, true))
        assertFalse(FastFailoverPolicy.canUseReadyReserve(true, false, true, true))
        assertTrue(FastFailoverPolicy.canUseReadyReserve(true, false, false, true))
    }

    @Test fun explicitManualChoiceDoesNotSilentlySwitchSources() {
        val chosen = node("manual", "one")
        val other = node("other", "two")
        val order = QuickConnectPolicy.order(
            selected = chosen, mode = ConnectionMode.MANUAL, explicitSelection = true,
            verified = listOf(other), historical = listOf(other),
            recentlyConnectedIds = listOf("other"), catalogue = listOf(other, chosen),
            publicRanks = mapOf("other" to 0)
        )
        assertEquals(listOf("manual"), order.map { it.id })
    }
}
