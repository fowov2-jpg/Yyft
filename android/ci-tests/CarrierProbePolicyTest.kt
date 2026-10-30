package com.secureconnect.app.ui.screens.settings

import org.junit.Assert.assertTrue
import org.junit.Test

class CarrierProbePolicyTest {
    @Test fun activeVpnDoesNotClaimThatMegafonBlockedAllFourSites() {
        val notice = CarrierProbePolicy.vpnActiveNotice()
        assertTrue(notice.contains("не запускалась"))
        assertTrue(notice.contains("VPN сейчас подключён"))
        assertTrue(notice.contains("не подтверждают блокировку"))
        assertTrue(notice.contains("Kill Switch не изменены"))
        assertTrue(notice.contains("Нельзя утверждать"))
        val oldScreenshot = CarrierProbePolicy.conclusion(true, false, false, true)
        assertTrue(oldScreenshot.contains("не запускалась"))
        assertTrue(!oldScreenshot.contains("Оба сайта не ответили"))
    }

    @Test fun noActiveVpnDoesNotInventOperatorClassification() {
        val unknown = CarrierProbePolicy.conclusion(true, false, false, false)
        assertTrue(unknown.contains("Причина не определена"))
        assertTrue(unknown.contains("Нельзя утверждать"))
    }


    @Test fun immediateVisibleProgressIncludesPreviousResults() {
        val text = CarrierProbePolicy.progress(2, 4, "Яндекс",
            listOf("VK: HTTP 200", "Обычный HTTPS: нет ответа"))
        assertTrue(text.contains("Проверка 2/4: Яндекс"))
        assertTrue(text.contains("VK: HTTP 200"))
        assertTrue(text.contains("Обычный HTTPS: нет ответа"))
    }


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
