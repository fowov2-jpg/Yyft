package com.secureconnect.app

/** Pure policy testable with JUnit without an Android runtime. */
internal object SessionTimerPolicy {
    val choicesHours = listOf(0, 1, 2, 3, 4, 6, 8, 12, 24)
    fun valid(hours: Int): Boolean = hours in choicesHours
    fun durationMs(hours: Int): Long {
        require(valid(hours)) { "Invalid session duration" }
        return hours.toLong() * 60L * 60L * 1000L
    }
    fun expired(nowWallMs: Long, wallDeadlineMs: Long,
                nowElapsedMs: Long, elapsedDeadlineMs: Long): Boolean =
        wallDeadlineMs > 0L && elapsedDeadlineMs > 0L &&
            (nowWallMs >= wallDeadlineMs || nowElapsedMs >= elapsedDeadlineMs)
}
