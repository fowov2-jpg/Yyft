package com.secureconnect.app.viewmodel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CatalogueStartupPolicyTest {
    @Test fun emptyCatalogBlocksVpnUntilFirstRealConfigsArrive() {
        val s = CatalogueStartupPolicy.resolve(false, 0, false,
            "Загружаю VPN-конфигурации: 0/240…")
        assertEquals(CatalogueStartupPolicy.Phase.LOADING, s.phase)
        assertFalse(s.ready)
    }
    @Test fun usablePersistentListMakesVpnAvailableWithoutUnnecessaryRedownload() {
        val s = CatalogueStartupPolicy.resolve(true, 240, false, "Загружаю список…")
        assertEquals(CatalogueStartupPolicy.Phase.READY_CACHE, s.phase)
        assertTrue(s.ready)
        assertTrue(s.detail.contains("240"))
    }
    @Test fun unusableListIsNotConsideredReadyEvenIfItContains240Strings() {
        assertFalse(CatalogueStartupPolicy.resolve(false, 240, false,
            "Загружаю VPN-конфигурации").ready)
    }
    @Test fun storedHttpsProvenFallbackWorksWithoutCatalogue() {
        val s = CatalogueStartupPolicy.resolve(false, 0, true, "Нет сети")
        assertTrue(s.ready)
        assertEquals(CatalogueStartupPolicy.Phase.READY_RECOVERY, s.phase)
    }
    @Test fun scannerFailureProvidesRetryInsteadOfInfiniteSpinner() {
        for (message in listOf("Нет сети", "Источники временно недоступны",
            "Не удалось загрузить источники", "Все источники отключены")) {
            val s = CatalogueStartupPolicy.resolve(false, 0, false, message)
            assertEquals(CatalogueStartupPolicy.Phase.ERROR, s.phase)
            assertFalse(s.ready)
        }
    }
    @Test fun bogusOrPartialProgressIsNotShownAsPercentComplete() {
        val s = CatalogueStartupPolicy.resolve(false, 5000, false, "")
        assertEquals(240, s.storedCount)
        assertFalse(s.ready)
        assertTrue(s.detail.contains("Загружается"))
    }
}