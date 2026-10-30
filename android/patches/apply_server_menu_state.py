#!/usr/bin/env python3
"""No-probe UI fix: active VPN != strict 720p reserve; trace menu vs one-tap."""
from pathlib import Path
import sys
if len(sys.argv)!=2: raise SystemExit("usage: apply_server_menu_state.py <SecureConnect root>")
root=Path(sys.argv[1])/"app/src"
main=root/"main/java/com/secureconnect/app"
def swap(rel, old, new):
    p=main/rel
    s=p.read_text(encoding="utf-8")
    if new in s: return
    if s.count(old)!=1: raise SystemExit(f"Missing/ambiguous anchor {rel}: {old[:55]}")
    p.write_text(s.replace(old,new,1),encoding="utf-8")

policy=main/"ui/screens/settings/ServersPresentationPolicy.kt"
body='''package com.secureconnect.app.ui.screens.settings
import com.secureconnect.app.vpn.VpnState

/** Certified video-quality backups do not determine current VPN connectivity. */
internal object ServersPresentationPolicy {
    fun title(state: VpnState, country: String?): String = when {
        state == VpnState.Connected && !country.isNullOrBlank() -> country
        state == VpnState.Connecting || state == VpnState.Validating -> "Подключение…"
        state == VpnState.Blocked -> "Защита активна · соединение прервано"
        else -> "Нет активного VPN"
    }
    fun emptyMessage(state: VpnState): String = when (state) {
        VpnState.Connected -> "Основной VPN подключён. Запасные серверы ещё не прошли отдельную проверку качества."
        VpnState.Connecting, VpnState.Validating -> "Подключение выполняется. Резервные серверы пока не подтверждены."
        else -> "Подтверждённых резервов пока нет. Это не число серверов в общем каталоге."
    }
}
'''
if policy.exists() and policy.read_text(encoding="utf-8")!=body: raise SystemExit("Unexpected presentation policy")
policy.write_text(body,encoding="utf-8")

ui="ui/screens/settings/PremiumScreens.kt"
swap(ui,'import androidx.compose.runtime.Composable\n','import androidx.compose.runtime.Composable\nimport androidx.compose.runtime.LaunchedEffect\n')
swap(ui,'import com.secureconnect.app.vpn.VpnController\n','import com.secureconnect.app.vpn.VpnController\nimport com.secureconnect.app.vpn.VpnState\n')
swap(ui,'fun PremiumServersScreen(vm: MainViewModel, onBack: () -> Unit) {\n    val active by VpnController.activeServer.collectAsStateWithLifecycle()',
'''fun PremiumServersScreen(vm: MainViewModel, onBack: () -> Unit) {
    // Observability only; opening the menu must not start scanning or connect.
    LaunchedEffect(vm) { vm.noteServersScreenOpened() }
    val vpnState by VpnController.state.collectAsStateWithLifecycle()
    val active by VpnController.activeServer.collectAsStateWithLifecycle()''')
swap(ui,'Text(active?.country?.takeIf { it.isNotBlank() } ?: "Нет подключения",\n                            color = ScTextPrimary,',
           'Text(ServersPresentationPolicy.title(vpnState, active?.country),\n                            color = ScTextPrimary,')
swap(ui,'NativeSectionTitle("Рабочие серверы · ${working.size}")','NativeSectionTitle("Проверенные резервы · ${working.size}")')
swap(ui,'Text("Рабочие серверы ещё не найдены.",\n                    color = ScTextSecondary,',
           'Text(ServersPresentationPolicy.emptyMessage(vpnState),\n                    color = ScTextSecondary,')

vm="viewmodel/MainViewModel.kt"
swap(vm,'    fun diagnosticReport(): String = VpnDiagnosticReporter.render(',
'''    private var lastOneTapTime = "not pressed in this process"
    private var lastServersOpenTime = "not opened in this process"
    private fun diagnosticClock(): String =
        SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date())

    fun noteServersScreenOpened() {
        lastServersOpenTime = "${diagnosticClock()} state=${VpnController.state.value.javaClass.simpleName} primary=${VpnController.activeServer.value != null} pending=${autoSelectionPending.value}"
    }

    fun diagnosticReport(): String = VpnDiagnosticReporter.render(''')
swap(vm,'            logs = _logs.value.toList()\n        )\n    )\n\n    init {',
'''            logs = _logs.value.toList()
        )
    ) + "\\nOne-tap button event: $lastOneTapTime" +
        "\\nServers menu opened: $lastServersOpenTime" +
        "\\nNote: opening Servers does not trigger Xray or server scans.\\n"

    init {''')
swap(vm,'    fun selectAutoServer() {',
'''    fun selectAutoServer() {
        lastOneTapTime = "${diagnosticClock()} state=${VpnController.state.value.javaClass.simpleName} cached=${_servers.value.size} pending=${autoSelectionPending.value}"
        setConnectionMode(ConnectionMode.AUTO)''')

test=root/"test/java/com/secureconnect/app/ui/screens/settings/ServersPresentationPolicyTest.kt"
test.parent.mkdir(parents=True,exist_ok=True)
t='''package com.secureconnect.app.ui.screens.settings
import com.secureconnect.app.vpn.VpnState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ServersPresentationPolicyTest {
    @Test fun currentVpnMustNotComeFromStaleServer() {
        assertEquals("Германия", ServersPresentationPolicy.title(VpnState.Connected, "Германия"))
        assertEquals("Нет активного VPN", ServersPresentationPolicy.title(VpnState.Idle, "Германия"))
        assertEquals("Подключение…", ServersPresentationPolicy.title(VpnState.Connecting, "Германия"))
    }
    @Test fun zeroReservesDoesNotMeanDisconnected() {
        assertTrue(ServersPresentationPolicy.emptyMessage(VpnState.Connected).contains("Основной VPN подключён"))
        assertTrue(ServersPresentationPolicy.emptyMessage(VpnState.Idle).contains("Это не число серверов"))
    }
}
'''
if test.exists() and test.read_text(encoding="utf-8")!=t: raise SystemExit("Unexpected test file")
test.write_text(t,encoding="utf-8")
print("Server menu state/tracing patch applied")
