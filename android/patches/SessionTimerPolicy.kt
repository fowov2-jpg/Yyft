package com.secureconnect.app

/** Pure policy testable with JUnit without an Android runtime. */
internal object SessionTimerPolicy {
    val choicesHours = listOf(0, 1, 2, 3, 4, 6, 8, 12, 24)
    /** Changing from unlimited must start a timer if a VPN is already active. */
    fun startOnChoice(hours: Int, previouslyTimed: Boolean, vpnInProgress: Boolean): Boolean =
        valid(hours) && hours > 0 && (previouslyTimed || vpnInProgress)

    fun valid(hours: Int): Boolean = hours in choicesHours
    fun durationMs(hours: Int): Long {
        require(valid(hours)) { "Invalid session duration" }
        return hours.toLong() * 60L * 60L * 1000L
    }
    /**
     * UI only: ceil to whole seconds so 00:00:00 is shown only when due.
     * Uses the saved deadline (not a newly started per-screen timer).
     */
    fun formatRemainingMs(remainingMs: Long): String {
        val safeMs = remainingMs.coerceAtLeast(0L)
        val totalSeconds = safeMs / 1000L + if (safeMs % 1000L > 0L) 1L else 0L
        val hours = totalSeconds / 3_600L
        val minutes = (totalSeconds % 3_600L) / 60L
        val seconds = totalSeconds % 60L
        return String.format(java.util.Locale.ROOT, "%02d:%02d:%02d", hours, minutes, seconds)
    }

    fun expired(nowWallMs: Long, wallDeadlineMs: Long,
                nowElapsedMs: Long, elapsedDeadlineMs: Long): Boolean =
        wallDeadlineMs > 0L && elapsedDeadlineMs > 0L &&
            (nowWallMs >= wallDeadlineMs || nowElapsedMs >= elapsedDeadlineMs)
}
