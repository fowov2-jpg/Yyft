package com.secureconnect.app.viewmodel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class OneTapRetryPolicyTest {
    @Test fun fourAttemptsPerWaveAndBoundedBatteryBackoff() {
        assertEquals(4, OneTapRetryPolicy.MAX_ATTEMPTS_PER_WAVE)
        assertEquals(20_000L, OneTapRetryPolicy.retryDelayMs(1))
        assertEquals(40_000L, OneTapRetryPolicy.retryDelayMs(2))
        assertEquals(90_000L, OneTapRetryPolicy.retryDelayMs(3))
        for (n in 4..100) assertEquals(180_000L, OneTapRetryPolicy.retryDelayMs(n))
    }

    @Test fun retryContinuesOnlyWithExplicitAutoSearchAndVpnPermission() {
        assertTrue(OneTapRetryPolicy.shouldContinue(true, true, false, false, true))
        assertFalse(OneTapRetryPolicy.shouldContinue(false, true, false, false, true))
        assertFalse(OneTapRetryPolicy.shouldContinue(true, false, false, false, true))
        assertFalse(OneTapRetryPolicy.shouldContinue(true, true, true, false, true))
        assertFalse(OneTapRetryPolicy.shouldContinue(true, true, false, true, true))
        assertFalse(OneTapRetryPolicy.shouldContinue(true, true, false, false, false))
    }
}
