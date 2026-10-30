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
import javax.net.ssl.HttpsURLConnection
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Explicit opt-in on the phone's cellular network.
 * Network.openConnection uses the selected physical network, bypassing the VPN.
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
    private fun probe(network: Network, url: String): Probe {
        val c = network.openConnection(URL(url)) as HttpsURLConnection
        try {
            c.connectTimeout = 3_500
            c.readTimeout = 3_500
            c.instanceFollowRedirects = false
            c.setRequestProperty("Accept", "text/html,application/json")
            c.setRequestProperty("Accept-Encoding", "identity")
            val status = c.responseCode
            return Probe("HTTP " + status, status in 200..399)
        } catch (_: java.io.IOException) {
            return Probe("нет ответа", false)
        } finally {
            c.disconnect()
        }
    }

    suspend fun run(context: Context): String = withContext(Dispatchers.IO) {
        val manager = context.getSystemService(Context.CONNECTIVITY_SERVICE)
            as? ConnectivityManager ?: return@withContext "Служба сети недоступна."
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
        val lines = mutableListOf("Прямые HTTPS-запросы через мобильную сеть:")
        val found = mutableMapOf<String, Boolean>()
        for (endpoint in endpoints) {
            val checked = probe(cellular, endpoint.uri)
            found[endpoint.label] = checked.reachable
            lines.add(endpoint.label + ": " + checked.text)
        }
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
            Text("Диагностика мобильной сети (МегаФон)",
                color = ScTextPrimary, style = MaterialTheme.typography.titleMedium)
            Text(
                "По нажатию будут выполнены четыре небольших HTTPS-запроса " +
                    "НАПРЯМУЮ через мобильный интернет, минуя VPN: VK, Яндекс, " +
                    "контрольный сайт и GitHub. Это раскрывает этим сайтам ваш " +
                    "мобильный IP-адрес. Ничего не отправляется в наш GitHub. " +
                    "Проверка доступности сайтов не доказывает ускорение VPN.",
                color = ScTextSecondary, style = MaterialTheme.typography.bodySmall)
            Button(enabled = !running, onClick = {
                running = true
                result = "Проверка мобильного интернета…"
                scope.launch {
                    try {
                        result = CarrierNetworkProbe.run(context.applicationContext)
                    } catch (e: CancellationException) {
                        throw e
                    } catch (_: Exception) {
                        result = "Проверка не завершилась. VPN не изменён."
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
