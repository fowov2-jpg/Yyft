package com.secureconnect.app

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/** Explicit non-exported alarm broadcast; does not initiate a new VPN. */
class SessionExpiryReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        if (intent?.action != "com.secureconnect.app.SESSION_EXPIRE") return
        if (!SessionTimer.expireIfDue(context)) SessionTimer.restoreAlarm(context)
    }
}
