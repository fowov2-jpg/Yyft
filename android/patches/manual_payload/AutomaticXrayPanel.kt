package com.secureconnect.app.ui.screens.settings

import android.app.Activity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.Button
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.secureconnect.app.ui.theme.ScTextPrimary
import com.secureconnect.app.ui.theme.ScTextSecondary
import com.secureconnect.app.viewmodel.MainViewModel
import com.secureconnect.app.vpn.AutomaticRoutePolicy
import com.secureconnect.app.vpn.VpnController
import com.secureconnect.app.vpn.VpnState

/**
 * Zero-gateway automated route using the ALREADY EXISTING native Xray one-tap.
 * Does not invent HTTP proxies, probe new hosts, restart a live tunnel, or
 * override Android's VPN permission dialog, STOP or Kill Switch.
 */
@Composable
fun AutomaticXrayPanel(vm: MainViewModel) {
    val vpnState by VpnController.state.collectAsStateWithLifecycle()
    val active by VpnController.activeServer.collectAsStateWithLifecycle()
    val pending by vm.autoSelectionPending.collectAsStateWithLifecycle()
    val isConnecting by vm.isConnecting.collectAsStateWithLifecycle()
    val autoConnect by vm.autoConnect.collectAsStateWithLifecycle()
    val autoRecovery by vm.autoRecovery.collectAsStateWithLifecycle()
    val serverCount by vm.servers.collectAsStateWithLifecycle()
    val readyCount by vm.readyWorkingCount.collectAsStateWithLifecycle()
    val error by vm.vpnError.collectAsStateWithLifecycle()
    var enableAutoAfterPermission by remember { mutableStateOf(false) }
    var consentDenied by remember { mutableStateOf(false) }
    val permissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { response ->
        if (response.resultCode == Activity.RESULT_OK) {
            consentDenied = false
            if (enableAutoAfterPermission) vm.setAutoConnect(true)
            else vm.selectAutoServer()
        } else consentDenied = true
        enableAutoAfterPermission = false
    }

    val action = AutomaticRoutePolicy.decide(vpnState, pending, isConnecting)
    Column(verticalArrangement = Arrangement.spacedBy(9.dp)) {
        Text("Автоматически — без HTTP-шлюза", color = ScTextPrimary)
        Text(
            "Приложение использует собственный каталог Xray, подключает доступный " +
                "сервер и сохраняет работающий VPN. Адрес прокси вводить не нужно.",
            color = ScTextSecondary
        )
        Text(AutomaticRoutePolicy.message(action, active != null), color = ScTextSecondary)
        if (vpnState == VpnState.Connected && active != null) {
            Text(
                "Текущий маршрут: ${active?.country.orEmpty()} · ${active?.protocol.orEmpty()} · " +
                    "${active?.host.orEmpty()}", color = ScTextPrimary
            )
        }
        Text(
            "Каталог: ${serverCount.size}; сертифицированный резерв: $readyCount. " +
                "Нулевой резерв сам по себе не означает отключение VPN.",
            color = ScTextSecondary
        )
        if (vpnState is VpnState.Error) {
            Text("Ошибка VPN: ${(vpnState as VpnState.Error).message}",
                color = ScTextSecondary)
        }
        if (error != null && action != AutomaticRoutePolicy.Action.KEEP_SESSION) {
            Text("Подключение: $error", color = ScTextSecondary)
        }
        if (consentDenied) {
            Text("Без системного согласия Android VPN не запускается.",
                color = ScTextSecondary)
        }
        Button(
            enabled = action == AutomaticRoutePolicy.Action.START_XRAY,
            onClick = {
                if (AutomaticRoutePolicy.decide(
                        VpnController.state.value,
                        vm.autoSelectionPending.value,
                        vm.isConnecting.value
                    ) != AutomaticRoutePolicy.Action.START_XRAY) return@Button
                vm.setConnectionMode(com.secureconnect.app.vpn.ConnectionMode.AUTO)
                val intent = vm.vpnPermissionIntent()
                enableAutoAfterPermission = false
                if (intent == null) vm.selectAutoServer()
                else permissionLauncher.launch(intent)
            }
        ) { Text("Подключить автоматически через Xray") }

        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("Автоподключение при запуске", color = ScTextPrimary,
                modifier = Modifier.weight(1f))
            Switch(
                checked = autoConnect,
                onCheckedChange = { enabled ->
                    if (!enabled) vm.setAutoConnect(false)
                    else {
                        vm.setConnectionMode(com.secureconnect.app.vpn.ConnectionMode.AUTO)
                        val consent = vm.vpnPermissionIntent()
                        if (consent == null) vm.setAutoConnect(true)
                        else {
                            enableAutoAfterPermission = true
                            permissionLauncher.launch(consent)
                        }
                    }
                }
            )
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("Автовосстановление Xray", color = ScTextPrimary,
                modifier = Modifier.weight(1f))
            Switch(checked = autoRecovery, onCheckedChange = vm::setAutoRecovery)
        }
        Text(
            "Включать фоновые HTTP-комбинации не нужно: известные VLESS-узлы " +
                "не являются HTTP CONNECT-прокси. Системное разрешение VPN " +
                "запрашивается штатным диалогом Android. " +
                "Если Kill Switch блокирует сеть, управление остаётся на главном экране.",
            color = ScTextSecondary
        )
    }
}
