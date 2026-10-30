package com.secureconnect.app.ui.screens.settings

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.secureconnect.app.ui.components.NativeGroup
import com.secureconnect.app.ui.theme.ScTextPrimary
import com.secureconnect.app.ui.theme.ScTextSecondary
import com.secureconnect.app.vpn.VpnController
import com.secureconnect.app.vpn.VpnState
import java.net.URL
import java.net.ConnectException
import java.net.NoRouteToHostException
import java.net.UnknownHostException
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.HttpsURLConnection
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Explicit opt-in on the phone's cellular network.
 * Network.openConnection selects a physical network, but Android may block
 * that network entirely while a VPN is connected (allowBypass/lockdown policy).
 * Never auto-run, never upload telemetry, never change VPN, SNI or routing.
 */
internal object CarrierNetworkProbe {
    private data class Probe(val text: String, val reachable: Boolean)
    private data class Target(val label: String, val uri: String)
    private val endpoints = listOf(
        Target("VK", "https://vk.com/"),
        Target("Яндекс", "https://ya.ru/"),
        Target("Обычный HTTPS", "https://www.gstatic.com/generate_204"),
        Target("GitHub-конфигурации", "https://fowov2-jpg.github.io/Yyft/candidates.json")
    )
    private fun probe(network: Network?, url: String): Probe {
        // A null Network intentionally measures the Android default route.
        // Both paths are read-only HTTPS, not proxy/TUN bypass configuration.
        var connection: HttpsURLConnection? = null
        return try {
            connection = if (network == null) {
                URL(url).openConnection() as HttpsURLConnection
            } else {
                network.openConnection(URL(url)) as HttpsURLConnection
            }
            connection.connectTimeout = 3_500
            connection.readTimeout = 3_500
            connection.instanceFollowRedirects = false
            connection.setRequestProperty("Accept", "text/html,application/json")
            connection.setRequestProperty("Accept-Encoding", "identity")
            val status = connection.responseCode
            Probe("HTTP " + status, status in 200..399)
        } catch (_: UnknownHostException) {
            Probe("DNS: имя не разрешилось", false)
        } catch (_: java.net.SocketTimeoutException) {
            Probe("тайм-аут", false)
        } catch (_: NoRouteToHostException) {
            Probe("маршрут отсутствует", false)
        } catch (_: ConnectException) {
            Probe("TCP: соединение отклонено/недоступно", false)
        } catch (_: SSLHandshakeException) {
            Probe("ошибка рукопожатия TLS", false)
        } catch (_: javax.net.ssl.SSLException) {
            Probe("ошибка TLS", false)
        } catch (_: SecurityException) {
            Probe("Android запретил подключение", false)
        } catch (_: java.io.IOException) {
            Probe("ошибка сети (иная)", false)
        } catch (_: RuntimeException) {
            Probe("ошибка сетевого API Android", false)
        } finally {
            connection?.disconnect()
        }
    }
    suspend fun run(context: Context, onProgress: (String) -> Unit): String =
        withContext(Dispatchers.IO) {
            suspend fun show(value: String) {
                withContext(Dispatchers.Main) { onProgress(value) }
            }
            show("Проверяю состояние VPN и мобильной сети…")
            // Explicit fail-closed preflight: an active VPN can prevent ALL
            // network.openConnection calls from bypassing its tunnel.
            // Do not produce false claims that MegaFon blocked every website.
            if (VpnController.state.value is VpnState.Connected) {
                return@withContext CarrierProbePolicy.vpnActiveNotice()
            }
            val manager = context.getSystemService(Context.CONNECTIVITY_SERVICE)
                as? ConnectivityManager
                ?: return@withContext "Служба сети Android недоступна."
            // Android may expose a cellular Network even while the default
            // traffic is on Wi-Fi or an always-on VPN. Distinguish those paths.
            val defaultCaps = try {
                manager.activeNetwork?.let { manager.getNetworkCapabilities(it) }
            } catch (_: SecurityException) { null }
            val transport = when {
                defaultCaps == null -> "не определена"
                defaultCaps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) -> "VPN"
                defaultCaps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "Wi-Fi"
                defaultCaps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "мобильная"
                else -> "другая"
            }
            if (transport != "мобильная") {
                return@withContext CarrierProbePolicy.unusableDefault(transport)
            }
            val cellular = try {
                manager.allNetworks.firstOrNull { n ->
                    val caps = manager.getNetworkCapabilities(n)
                    caps?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true &&
                        !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
                }
            } catch (_: SecurityException) { null }
            if (cellular == null) {
                return@withContext CarrierProbePolicy.conclusion(
                    cellular = false, vk = false, ordinaryHttps = false, vpnConnected = false)
            }
            val caps = try { manager.getNetworkCapabilities(cellular) }
                       catch (_: SecurityException) { null }
            val lines = mutableListOf(
                "Прямые HTTPS-запросы через мобильную сеть:",
                CarrierProbePolicy.mobileNetworkSummary(
                    caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) == true,
                    caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) == true)
            )
            val found = mutableMapOf<String, Boolean>()
            for ((index, endpoint) in endpoints.withIndex()) {
                show(CarrierProbePolicy.progress(index + 1, endpoints.size,
                    endpoint.label, lines))
                val checked = probe(cellular, endpoint.uri)
                found[endpoint.label] = checked.reachable
                lines.add(endpoint.label + ": " + checked.text)
                show(CarrierProbePolicy.progress(
                    index + 1, endpoints.size, "следующий этап", lines))
            }
            show("Дополнительная проверка: системный маршрут Android…\n" +
                lines.joinToString("\n"))
            // One extra small HTTPS GET on the default Android route.
            // Only run when the default is cellular AND no VPN is active.
            val defaultControl = probe(
                null, "https://www.gstatic.com/generate_204")
            lines.add("Системный маршрут Android: " + defaultControl.text)
            lines.add(CarrierProbePolicy.routeComparison(
                found["Обычный HTTPS"] == true, defaultControl.reachable))
            val connected = VpnController.state.value is VpnState.Connected
            lines.add(CarrierProbePolicy.conclusion(
                cellular = true,
                vk = found["VK"] == true,
                ordinaryHttps = found["Обычный HTTPS"] == true,
                vpnConnected = connected
            ))
            lines.joinToString("\n")
        }
}

@Composable
internal fun CarrierNetworkDiagnosticsCard() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var running by remember { mutableStateOf(false) }
    var result by remember { mutableStateOf(
        "Проверка не запускалась. VPN и его настройки не изменяются."
    ) }
    NativeGroup {
        Column(Modifier.fillMaxWidth().padding(18.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text("Диагностика мобильной сети (оператор не определён)",
                color = ScTextPrimary, style = MaterialTheme.typography.titleMedium)
            Text(
                "При подключённом VPN тест не запускается. Без VPN и при мобильной " +
                    "сети по умолчанию проверяются четыре HTTPS-сайта и ещё один " +
                    "небольшой контрольный запрос через системный маршрут Android. " +
                    "Покажем DNS, TCP, TLS или тайм-аут вместо общей ошибки. " +
                    "Сайты увидят мобильный IP-адрес. Ничего не отправляется " +
                    "в наш GitHub. Оператор SIM не определяется автоматически. " +
                    "Доступность сайтов не доказывает ускорение VPN.",
                color = ScTextSecondary, style = MaterialTheme.typography.bodySmall)
            Button(enabled = !running, onClick = {
                running = true
                result = "Кнопка нажата. Начинаю проверку мобильной сети…"
                scope.launch {
                    try {
                        val answer = withTimeoutOrNull(35_000L) {
                            CarrierNetworkProbe.run(context.applicationContext) {
                                progress -> result = progress
                            }
                        }
                        result = answer ?: result + "\nПревышено время ожидания. Повторите позже."
                    } catch (e: CancellationException) {
                        throw e
                    } catch (_: Exception) {
                        result += "\nПроверка завершилась ошибкой. VPN не изменён."
                    } finally {
                        running = false
                    }
                }
            }) { Text(if (running) "Проверяется…" else "Проверить через SIM-карту") }
            Text(result, color = ScTextSecondary,
                style = MaterialTheme.typography.bodySmall)
        }
    }
}
