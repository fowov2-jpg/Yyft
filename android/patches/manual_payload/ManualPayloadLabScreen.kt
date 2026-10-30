package com.secureconnect.app.ui.screens.settings

import android.content.Context
import android.os.SystemClock
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.unit.dp
import com.secureconnect.app.ui.components.ScreenTopBar
import com.secureconnect.app.ui.theme.ScBackground
import com.secureconnect.app.ui.theme.ScTextPrimary
import com.secureconnect.app.ui.theme.ScTextSecondary
import com.secureconnect.app.vpn.ManualPayloadCodec
import com.secureconnect.app.vpn.ManualPayloadGatewayProbe
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Manual user-authored HTTP payload, preview, local save and one explicit probe.
 * Deliberately NOT an Xray outbound: raw HTTP-BUG is not Xray's VLESS transport.
 */
@Composable
fun ManualPayloadLabScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val prefs = remember(context) {
        context.getSharedPreferences("manual_payload_lab_v1", Context.MODE_PRIVATE)
    }
    var gateway by remember { mutableStateOf(prefs.getString("gateway", "") ?: "") }
    var port by remember { mutableStateOf(prefs.getString("port", "443") ?: "443") }
    var template by remember {
        mutableStateOf(prefs.getString("template", ManualPayloadCodec.USER_TEMPLATE)
            ?: ManualPayloadCodec.USER_TEMPLATE)
    }
    var useTls by remember { mutableStateOf(prefs.getBoolean("tls", true)) }
    var useCellular by remember { mutableStateOf(prefs.getBoolean("cellular", true)) }
    var result by remember { mutableStateOf("Проверка ещё не запускалась.") }
    var running by remember { mutableStateOf(false) }
    var lastTestAt by remember { mutableLongStateOf(0L) }
    val clipboard = LocalClipboardManager.current
    val scope = rememberCoroutineScope()
    val encoding = remember(template) { ManualPayloadCodec.encode(template) }
    val warning = remember(gateway, port, useTls) {
        ManualPayloadCodec.configurationWarning(gateway, port, useTls)
    }

    Column(Modifier.fillMaxSize().background(ScBackground)) {
        ScreenTopBar("HTTP Payload · вручную", onBack = onBack)
        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            item {
                Text("Ручной тест HTTP-запроса к указанному тобой шлюзу.",
                    color = ScTextPrimary)
                Text("НЕ меняет Xray, VPN и сервер Германии. Ответ HTTP не доказывает " +
                    "работу VPN или прохождение белого списка.", color = ScTextSecondary)
            }
            item {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(onClick = {
                        template = ManualPayloadCodec.USER_TEMPLATE
                    }) { Text("Твой шаблон") }
                    OutlinedButton(onClick = {
                        template = ManualPayloadCodec.STANDARD_TEMPLATE
                    }) { Text("Обычный CONNECT") }
                }
            }
            item {
                OutlinedButton(onClick = {
                    template = ManualPayloadCodec.WEBSITE_TEMPLATE
                }) { Text("Проверка сайта (GET), не VPN") }
            }
            item {
                OutlinedTextField(
                    value = gateway, onValueChange = { gateway = it.take(253) },
                    label = { Text("Адрес своего / разрешённого HTTP-шлюза") },
                    modifier = Modifier.fillMaxWidth(), singleLine = true
                )
                OutlinedTextField(
                    value = port, onValueChange = {
                        port = it.filter(Char::isDigit).take(5)
                    },
                    label = { Text("Порт шлюза") }, singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
            }
            item {
                if (warning != null) {
                    Text("Внимание: $warning", color = ScTextSecondary)
                }
            }
            item {
                OutlinedTextField(
                    value = template, onValueChange = { template = it.take(4096) },
                    label = { Text("HTTP Payload ([crlf] — новая строка)") },
                    modifier = Modifier.fillMaxWidth(), minLines = 7, maxLines = 12
                )
                Text(
                    encoding.error ?: "Готово: ${encoding.bytes.size} байт, один запрос.",
                    color = ScTextSecondary
                )
            }
            item {
                if (encoding.valid) {
                    Text("Предпросмотр передаваемого HTTP-запроса:",
                        color = ScTextPrimary)
                    Text(encoding.preview.take(1000), color = ScTextSecondary)
                }
            }
            item {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("TLS до шлюза (проверка сертификата)", color = ScTextPrimary,
                        modifier = Modifier.weight(1f))
                    Switch(checked = useTls, onCheckedChange = { useTls = it })
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("Тестировать через мобильную SIM", color = ScTextPrimary,
                        modifier = Modifier.weight(1f))
                    Switch(checked = useCellular, onCheckedChange = { useCellular = it })
                }
            }
            item {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onClick = {
                        if (!encoding.valid) {
                            result = encoding.error ?: "Ошибка запроса"
                        } else {
                            prefs.edit().putString("gateway", gateway)
                                .putString("port", port)
                                .putString("template", template)
                                .putBoolean("tls", useTls)
                                .putBoolean("cellular", useCellular)
                                .apply()
                            result = "Сохранено локально. VPN-конфигурация НЕ изменена."
                        }
                    }) { Text("Сохранить") }
                    OutlinedButton(onClick = {
                        clipboard.setText(AnnotatedString(template))
                        result = "Шаблон скопирован."
                    }) { Text("Копировать") }
                }
            }
            item {
                Button(
                    onClick = {
                        if (running) return@Button
                        val now = SystemClock.elapsedRealtime()
                        if (lastTestAt != 0L && now - lastTestAt < 20_000L) {
                            result = "Не чаще одного теста в 20 секунд."
                            return@Button
                        }
                        if (!encoding.valid) {
                            result = encoding.error ?: "Неверный HTTP-запрос"
                            return@Button
                        }
                        lastTestAt = now
                        running = true
                        result = "Одна проверка выбранного шлюза. Без автоповторов…"
                        scope.launch {
                            result = withContext(Dispatchers.IO) {
                                ManualPayloadGatewayProbe.run(context.applicationContext,
                                    gateway, port, useCellular, useTls, encoding)
                            }
                            running = false
                        }
                    },
                    enabled = !running && encoding.valid
                ) { Text(if (running) "Проверяется…" else "Проверить один раз") }
                Text(result, color = ScTextPrimary)
                OutlinedButton(onClick = {
                    clipboard.setText(AnnotatedString(
                        "Ручной HTTP Payload (VipineshkaVPN)\n" +
                        "Тип: ${if (useTls) "TLS" else "RAW"}; " +
                        "Сеть: ${if (useCellular) "SIM" else "Wi-Fi"}\n" +
                        "Шлюз: $gateway:$port\n" +
                        "Запрос: $template\n" +
                        "Ответ: $result\n" +
                        "VPN / белый список: НЕ подтверждены."
                    ))
                }) { Text("Скопировать профиль и результат") }
            }
            item {
                Text("Проверка выполняется с телефона через выбранную физическую сеть, " +
                    "но не через Xray. В режиме RAW заголовки видны оператору. " +
                    "Не вставляй пароли, токены и секретные ссылки. " +
                    "Нет сканирования, автоматического перебора или нагрузочного теста.",
                    color = ScTextSecondary)
            }
        }
    }
}
