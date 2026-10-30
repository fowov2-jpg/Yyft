package com.secureconnect.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SessionTimerPolicyTest {
    @Test fun validChoicesCoverTwoHoursThroughOneDay() {
        assertEquals(listOf(0, 1, 2, 3, 4, 6, 8, 12, 24), SessionTimerPolicy.choicesHours)
        assertEquals(7_200_000L, SessionTimerPolicy.durationMs(2))
        assertEquals(86_400_000L, SessionTimerPolicy.durationMs(24))
        assertFalse(SessionTimerPolicy.valid(25))
    }
    @Test fun changingUnlimitedToTwoHoursDuringVpnStartsCountdown() {
        assertTrue(SessionTimerPolicy.startOnChoice(2, false, true))
        assertTrue(SessionTimerPolicy.startOnChoice(24, true, false))
        assertFalse(SessionTimerPolicy.startOnChoice(0, true, true))
        assertFalse(SessionTimerPolicy.startOnChoice(2, false, false))
        assertFalse(SessionTimerPolicy.startOnChoice(25, true, true))
    }

    @Test fun countdownDisplaysHoursMinutesSecondsWithoutRestart() {
        assertEquals("02:00:00", SessionTimerPolicy.formatRemainingMs(7_200_000L))
        assertEquals("01:42:18", SessionTimerPolicy.formatRemainingMs(6_138_000L))
        assertEquals("00:00:01", SessionTimerPolicy.formatRemainingMs(1L))
        assertEquals("00:00:00", SessionTimerPolicy.formatRemainingMs(0L))
        assertEquals("00:00:00", SessionTimerPolicy.formatRemainingMs(-20L))
        assertEquals("24:00:00", SessionTimerPolicy.formatRemainingMs(86_400_000L))
    }

    @Test fun deadlineCheckUsesEitherClockAndIgnoresInactiveTimer() {
        assertFalse(SessionTimerPolicy.expired(8, 0, 10, 0))
        assertFalse(SessionTimerPolicy.expired(499, 500, 899, 900))
        assertTrue(SessionTimerPolicy.expired(500, 500, 899, 900))
        assertTrue(SessionTimerPolicy.expired(499, 500, 900, 900))
    }
}
