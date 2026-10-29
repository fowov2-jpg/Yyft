package com.secureconnect.app

import android.app.ActivityManager
import android.app.AlarmManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.SystemClock

/** Persisted one-tap VPN usage limit. Never extend during auto-retry/reconnect. */
internal object SessionTimer {
    private const val PREFS = "sc_session_timer_v1"
    private const val HOURS = "selected_hours"
    private const val WALL_DEADLINE = "deadline_wall_ms"
    private const val ELAPSED_DEADLINE = "deadline_elapsed_ms"
    private const val REQUEST_CODE = 4101

    private fun prefs(context: Context) = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
    fun selectedHours(context: Context): Int = prefs(context).getInt(HOURS, 0)
        .takeIf(SessionTimerPolicy::valid) ?: 0

    /** Selecting a duration during an active session starts a new countdown now. */
    fun choose(context: Context, hours: Int) {
        require(SessionTimerPolicy.valid(hours))
        val active = hasActiveSession(context)
        prefs(context).edit().putInt(HOURS, hours).commit()
        if (active) {
            cancelActive(context)
            if (hours != 0) startIfNeeded(context)
        }
    }

    fun hasActiveSession(context: Context): Boolean =
        prefs(context).getLong(WALL_DEADLINE, 0L) > 0L

    fun remainingMs(context: Context): Long? {
        val p = prefs(context)
        val wall = p.getLong(WALL_DEADLINE, 0L)
        val elapsed = p.getLong(ELAPSED_DEADLINE, 0L)
        if (wall <= 0L || elapsed <= 0L) return null
        return minOf(wall - System.currentTimeMillis(), elapsed - SystemClock.elapsedRealtime())
            .coerceAtLeast(0L)
    }

    /** Start once per intended session, never reset on server switches. */
    @Synchronized fun startIfNeeded(context: Context) {
        val hours = selectedHours(context)
        if (hours == 0) return
        if (hasActiveSession(context)) {
            if (!expireIfDue(context)) scheduleAlarm(context)
            return
        }
        val duration = SessionTimerPolicy.durationMs(hours)
        prefs(context).edit()
            .putLong(WALL_DEADLINE, System.currentTimeMillis() + duration)
            .putLong(ELAPSED_DEADLINE, SystemClock.elapsedRealtime() + duration)
            .commit()
        scheduleAlarm(context)
    }

    fun restoreAlarm(context: Context) {
        if (hasActiveSession(context) && !expireIfDue(context)) scheduleAlarm(context)
    }

    @Synchronized fun cancelActive(context: Context) {
        prefs(context).edit().remove(WALL_DEADLINE).remove(ELAPSED_DEADLINE).commit()
        (context.getSystemService(Context.ALARM_SERVICE) as? AlarmManager)
            ?.cancel(alarmIntent(context))
        alarmIntent(context).cancel()
    }

    /** Expired sessions close TUN, stop scanner/recovery, then remove our task. */
    @Synchronized fun expireIfDue(context: Context): Boolean {
        val p = prefs(context)
        val wall = p.getLong(WALL_DEADLINE, 0L)
        val elapsed = p.getLong(ELAPSED_DEADLINE, 0L)
        if (!SessionTimerPolicy.expired(System.currentTimeMillis(), wall,
                SystemClock.elapsedRealtime(), elapsed)) return false
        cancelActive(context)
        AppRunController.closed(context)
        // Android does not allow a third-party app to force-stop its own package.
        (context.getSystemService(ActivityManager::class.java))?.appTasks
            ?.forEach { runCatching { it.finishAndRemoveTask() } }
        return true
    }

    private fun alarmIntent(context: Context): PendingIntent = PendingIntent.getBroadcast(
        context, REQUEST_CODE,
        Intent(context, SessionExpiryReceiver::class.java)
            .setAction("com.secureconnect.app.SESSION_EXPIRE"),
        PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
    )

    private fun scheduleAlarm(context: Context) {
        val remaining = remainingMs(context) ?: return
        val trigger = SystemClock.elapsedRealtime() + remaining.coerceAtLeast(1_000L)
        val manager = context.getSystemService(Context.ALARM_SERVICE) as? AlarmManager ?: return
        // No exact-alarm privilege requested; Android Doze may delay the alarm.
        manager.setAndAllowWhileIdle(AlarmManager.ELAPSED_REALTIME_WAKEUP,
            trigger, alarmIntent(context))
    }
}
