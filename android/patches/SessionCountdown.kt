package com.secureconnect.app.ui.screens.home

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.secureconnect.app.SessionTimer
import com.secureconnect.app.SessionTimerPolicy
import com.secureconnect.app.ui.theme.ScTextSecondary
import kotlinx.coroutines.delay

/**
 * 1 Hz foreground-only rendering of the existing persisted deadline.
 * Not a second timer; background alarms and service guards remain responsible
 * for expiry. Display updates resume automatically after returning to the app.
 */
@Composable
internal fun SessionCountdown() {
    val context = LocalContext.current
    val owner = LocalLifecycleOwner.current
    val lifecycleState by owner.lifecycle.currentStateFlow.collectAsState()
    var selectedHours by remember(context) { mutableIntStateOf(SessionTimer.selectedHours(context)) }
    var remainingMs by remember(context) { mutableStateOf(SessionTimer.remainingMs(context)) }

    LaunchedEffect(lifecycleState, context) {
        if (lifecycleState.isAtLeast(Lifecycle.State.RESUMED)) {
            while (true) {
                selectedHours = SessionTimer.selectedHours(context)
                remainingMs = SessionTimer.remainingMs(context)
                // If Android delayed the alarm while this screen stays visible,
                // honour the deadline without extending or resetting it.
                if (remainingMs == 0L && SessionTimer.hasActiveSession(context)) {
                    SessionTimer.expireIfDue(context)
                }
                delay(1_000L)
            }
        }
    }

    if (selectedHours <= 0) return
    val shape = RoundedCornerShape(18.dp)
    Column(
        modifier = Modifier.fillMaxWidth()
            .background(Color(0xFF172C39), shape)
            .border(1.dp, Color(0xFF385565), shape)
            .padding(horizontal = 18.dp, vertical = 14.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp)
    ) {
        Text(
            "ТАЙМЕР ОТКЛЮЧЕНИЯ",
            style = MaterialTheme.typography.labelSmall,
            color = ScTextSecondary,
            fontWeight = FontWeight.Bold
        )
        if (remainingMs != null) {
            Text(
                "Осталось " + SessionTimerPolicy.formatRemainingMs(remainingMs!!),
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.Bold,
                color = Color(0xFFDDECF7)
            )
            Text(
                "VPN автоматически отключится по окончании времени",
                style = MaterialTheme.typography.bodySmall,
                color = ScTextSecondary
            )
        } else {
            Text(
                "Выбрано: " + selectedHours + " ч · отсчёт с подключения",
                style = MaterialTheme.typography.bodyMedium,
                color = Color(0xFFDDECF7)
            )
        }
    }
}
