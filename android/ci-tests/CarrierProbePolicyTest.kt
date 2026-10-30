package com.secureconnect.app.ui.screens.settings

import org.junit.Assert.assertTrue
import org.junit.Test

class CarrierProbePolicyTest {
    @Test fun selectiveVkReachabilityIsNotPresentedAsProofOfVpnWhitelisting() {
        val msg = CarrierProbePolicy.conclusion(true, true, false, true)
        assertTrue(msg.contains("VK отвечает"))
        assertTrue(msg.contains("Xray сообщает"))
        assertTrue(msg.contains("Нельзя утверждать"))
    }

    @Test fun bothReachableNeverClaimsOperatorBoost() {
        val msg = CarrierProbePolicy.conclusion(true, true, true, true)
        assertTrue(msg.contains("Различий доступности"))
        assertTrue(msg.contains("Нельзя утверждать"))
    }

    @Test fun noMobileNetworkRequiresActualSimTest() {
        val msg = CarrierProbePolicy.conclusion(false, false, false, false)
        assertTrue(msg.contains("Мобильная сеть не найдена"))
        assertTrue(msg.contains("не определён"))
    }

    @Test fun inconclusiveStatesDoNotImplyBypass() {
        for (vk in listOf(false, true)) {
            for (ordinary in listOf(false, true)) {
                for (connected in listOf(false, true)) {
                    assertTrue(CarrierProbePolicy.conclusion(
                        true, vk, ordinary, connected).contains("Нельзя утверждать"))
                }
            }
        }
    }
}
