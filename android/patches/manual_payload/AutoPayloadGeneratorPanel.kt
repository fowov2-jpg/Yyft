package com.secureconnect.app.ui.screens.settings

import android.content.Context
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.secureconnect.app.ui.theme.ScTextPrimary
import com.secureconnect.app.ui.theme.ScTextSecondary
import com.secureconnect.app.vpn.AutoPayloadGatewayProbe
import com.secureconnect.app.vpn.AutoPayloadGenerator
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Purely opt-in sequential search; screen disposal cancels subsequent attempts. */
@Composable
fun AutoPayloadGeneratorPanel(
    gateway: String, port: String, cellular: Boolean, tls: Boolean,
    onFound: (String) -> Unit
) {
    val context = LocalContext.current.applicationContext
    val prefs = remember(context) {
        context.getSharedPreferences("manual_payload_lab_v1", Context.MODE_PRIVATE)
    }
    var front by remember {
        mutableStateOf(prefs.getString("generator_front_host", "vk.com") ?: "vk.com")
    }
    var running by remember { mutableStateOf(false) }
    var status by remember {
        mutableStateOf("Автоперебор ещё не запускался. Шлюз должен быть твоим или разрешённым.")
    }
    var progress by remember { mutableStateOf("0 / 24") }
    val coroutineScope = rememberCoroutineScope()
    val jobHolder = remember { mutableStateOf<Job?>(null) }

    DisposableEffect(Unit) {
        onDispose { jobHolder.value?.cancel() }
    }
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text("Автогенератор CONNECT-комбинаций", color = ScTextPrimary)
        Text(
            "Сам перебирает изменения Host, CONNECT и дополнительных HTTP-заголовков. " +
                "Одна попытка за раз, до 24 вариантов, остановка на проверенном HTTPS " +
                "через HTTP-прокси. Не переключает действующий Xray.",
            color = ScTextSecondary
        )
        OutlinedTextField(
            value = front, onValueChange = { front = it.take(253) },
            label = { Text("Вариант заголовка Host (например, vk.com)") },
            modifier = Modifier.fillMaxWidth(), singleLine = true
        )
        Text(
            "Важно: TLS SNI и TCP IP относятся к указанному шлюзу, а не к Host. " +
                "Генератор не превращает VK в прокси и не гарантирует whitelist.",
            color = ScTextSecondary
        )
        Text("Попытки: $progress", color = ScTextPrimary)
        Text(status, color = ScTextSecondary)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(
                enabled = !running,
                onClick = {
                    if (running) return@Button
                    val candidates = AutoPayloadGenerator.generate(front)
                    val tcpPort = port.toIntOrNull()
                    if (candidates.isEmpty()) {
                        status = "Неверное имя Host для генерации."
                        return@Button
                    }
                    if (!AutoPayloadGenerator.isValidHost(gateway.trim()) ||
                        tcpPort == null || tcpPort !in 1..65535 ||
                        gateway.trim().equals("vk.com", true) ||
                        gateway.trim().equals("www.vk.com", true)) {
                        status = "Укажи свой/разрешённый HTTP CONNECT-шлюз и порт. " +
                            "Сайт vk.com не является нашим прокси."
                        return@Button
                    }
                    val thermal = AutoPayloadGatewayProbe.stopReason(context)
                    if (thermal != null) {
                        status = "Автоперебор не запущен: $thermal"
                        return@Button
                    }
                    prefs.edit().putString("generator_front_host", front).apply()
                    status = "Начат перебор ${candidates.size} комбинаций, без фона."
                    progress = "0 / ${candidates.size}"
                    running = true
                    jobHolder.value = coroutineScope.launch {
                        var found = false
                        var attempts = 0
                        try {
                            for (candidate in candidates) {
                                if (!isActive) break
                                val pause = AutoPayloadGatewayProbe.stopReason(context)
                                if (pause != null) {
                                    status = "Остановлено: $pause; проверено $attempts"
                                    break
                                }
                                attempts += 1
                                progress = "$attempts / ${candidates.size}"
                                status = "Проверяю ${candidate.label}"
                                val proof = withContext(Dispatchers.IO) {
                                    AutoPayloadGatewayProbe.attempt(
                                        context, gateway, tcpPort, cellular, tls, candidate
                                    )
                                }
                                if (!isActive) break
                                status = "Попытка $attempts: ${proof.stage} · ${proof.detail}"
                                if (proof.success) {
                                    found = true
                                    prefs.edit()
                                        .putString("template", candidate.template)
                                        .putString("gateway", gateway)
                                        .putString("port", port)
                                        .putBoolean("tls", tls)
                                        .putBoolean("cellular", cellular)
                                        .apply()
                                    onFound(candidate.template)
                                    status = "НАЙДЕН HTTP CONNECT! Попытка $attempts. " +
                                        "HTTPS через шлюз подтвердился. " +
                                        "Шаблон сохранён. Это НЕ подтверждение VPN Германии."
                                    break
                                }
                                delay(AutoPayloadGenerator.GAP_MS)
                            }
                            if (!found && isActive && attempts == candidates.size) {
                                status = "Все ${candidates.size} комбинаций проверены. " +
                                    "Подтверждённого HTTPS-туннеля через этот шлюз нет. " +
                                    "Не запускаю повтор, чтобы не нагревать телефон."
                            }
                        } finally {
                            running = false
                        }
                    }
                }
            ) { Text("Сгенерировать и проверить") }
            OutlinedButton(
                enabled = running,
                onClick = {
                    jobHolder.value?.cancel()
                    status = "STOP: новые попытки отменены; текущий сокет завершит работу по тайм-ауту."
                }
            ) { Text("STOP") }
        }
    }
}
