#!/usr/bin/env python3
"""Apply persisted user-selected VPN session shutdown to unpacked Android sources.
This patch must run AFTER apply_one_tap.py and fails on changed source anchors.
"""
from pathlib import Path
import shutil
import sys

root = Path(sys.argv[1]).resolve()
here = Path(__file__).resolve().parent
main = root / "app/src/main/java/com/secureconnect/app"

def replace(path, before, after):
    text = path.read_text(encoding="utf-8")
    if text.count(before) != 1:
        raise RuntimeError("Session timer source anchor mismatch: " + path.name + " / " + before[:70])
    path.write_text(text.replace(before, after, 1), encoding="utf-8")

for name in ("SessionTimer.kt", "SessionTimerPolicy.kt", "SessionExpiryReceiver.kt"):
    shutil.copyfile(here / name, main / name)

replace(root / "app/src/main/AndroidManifest.xml",
    "    </application>",
    '''        <receiver android:name=".SessionExpiryReceiver" android:exported="false" />
    </application>''')

activity = main / "MainActivity.kt"
replace(activity,
    "        AppRunController.opened(this)\n        reconcileVpnOnOpen()",
    """        if (SessionTimer.expireIfDue(this)) {
            finishAndRemoveTask()
            return
        }
        AppRunController.opened(this)
        SessionTimer.restoreAlarm(this)
        reconcileVpnOnOpen()""")
replace(activity,
    "        ScannerUiVisibility.visible = true",
    """        if (SessionTimer.expireIfDue(this)) {
            finishAndRemoveTask()
            return
        }
        ScannerUiVisibility.visible = true""")

replace(main / "AppRunController.kt",
    "    fun closed(context: Context) {\n        TlsRiskStore.clearApprovals()",
    """    fun closed(context: Context) {
        SessionTimer.cancelActive(context)
        TlsRiskStore.clearApprovals()""")

vm = main / "viewmodel/MainViewModel.kt"
replace(vm, "import com.secureconnect.app.AppRunController",
    "import com.secureconnect.app.AppRunController\nimport com.secureconnect.app.SessionTimer")
replace(vm,
    "    fun connect() {\n        if (_isConnecting.value || _isConnected.value) return",
    """    fun connect() {
        if (SessionTimer.expireIfDue(getApplication()) ||
            !AppRunController.mayRun(getApplication())) return
        if (_isConnecting.value || _isConnected.value) return""")
replace(vm,
    "    fun selectAutoServer() {\n        setConnectionMode(ConnectionMode.AUTO)",
    """    fun selectAutoServer() {
        if (SessionTimer.expireIfDue(getApplication()) ||
            !AppRunController.mayRun(getApplication())) return
        setConnectionMode(ConnectionMode.AUTO)""")
replace(vm,
    "        autoSelection.request()\n        refreshWorkingPool()",
    """        SessionTimer.startIfNeeded(getApplication())
        autoSelection.request()
        refreshWorkingPool()""")
replace(vm,
    "        // VPN is latency-sensitive. Stop subscription refresh/probing so one of",
    """        SessionTimer.startIfNeeded(getApplication())
        // VPN is latency-sensitive. Stop subscription refresh/probing so one of""")
replace(vm,
    "    fun disconnect() {\n        cancelAutoSelection()",
    """    fun disconnect() {
        SessionTimer.cancelActive(getApplication())
        cancelAutoSelection()""")

vpn = main / "vpn/XrayVpnService.kt"
replace(vpn, "import com.secureconnect.app.AppRunController",
    "import com.secureconnect.app.AppRunController\nimport com.secureconnect.app.SessionTimer")
replace(vpn,
    "    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {",
    """    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (SessionTimer.expireIfDue(this)) return START_NOT_STICKY""")
replace(vpn,
    "            ACTION_STOP, ACTION_STOP_FROM_NOTIFICATION, ACTION_STOP_FROM_TASK -> {\n                VpnController.speedTestResult.value = null",
    """            ACTION_STOP, ACTION_STOP_FROM_NOTIFICATION, ACTION_STOP_FROM_TASK -> {
                if (intent.action != ACTION_STOP) SessionTimer.cancelActive(this)
                VpnController.speedTestResult.value = null""")

replace(main / "ServerScanService.kt",
    "    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {",
    """    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (SessionTimer.expireIfDue(this)) return START_NOT_STICKY""")

settings = main / "ui/screens/settings/PremiumScreens.kt"
replace(settings, "import androidx.compose.foundation.layout.Arrangement",
    """import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material3.FilterChip
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableLongStateOf
import kotlinx.coroutines.delay
import com.secureconnect.app.SessionTimer
import com.secureconnect.app.SessionTimerPolicy""")
replace(settings,
    "    val context = LocalContext.current\n    var publicUrl",
    """    val context = LocalContext.current
    var timerHours by remember { mutableIntStateOf(SessionTimer.selectedHours(context)) }
    var timerTick by remember { mutableLongStateOf(System.currentTimeMillis()) }
    LaunchedEffect(Unit) {
        while (true) {
            timerTick = System.currentTimeMillis()
            delay(15_000L)
        }
    }
    var publicUrl""")
replace(settings,
    '            item { NativeSectionTitle("Безопасность и маршруты") }',
    '''            item { NativeSectionTitle("Таймер работы VPN") }
            item {
                NativeGroup {
                    Column(Modifier.fillMaxWidth().padding(18.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text("Отключить и закрыть через", color = ScTextPrimary,
                            style = MaterialTheme.typography.titleMedium)
                        Row(Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
                            horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            SessionTimerPolicy.choicesHours.forEach { hours ->
                                FilterChip(
                                    selected = timerHours == hours,
                                    onClick = {
                                        SessionTimer.choose(context, hours)
                                        timerHours = hours
                                        timerTick = System.currentTimeMillis()
                                    },
                                    label = {
                                        Text(if (hours == 0) "Без ограничения" else hours.toString() + " ч")
                                    }
                                )
                            }
                        }
                        val remaining = SessionTimer.remainingMs(context).also { timerTick }
                        val stateText = if (remaining != null) {
                            val totalMinutes = (remaining + 59_999L) / 60_000L
                            "Осталось: " + (totalMinutes / 60) + " ч " + (totalMinutes % 60) + " мин"
                        } else if (timerHours == 0) {
                            "Таймер отключён"
                        } else {
                            "Таймер запустится при нажатии «Подключить»"
                        }
                        Text(stateText, color = ScTextSecondary,
                            style = MaterialTheme.typography.bodySmall)
                        Text("По истечении VPN и фоновый поиск остановятся, " +
                            "экран приложения закроется. Интернет после отключения VPN " +
                            "может перейти на прямое соединение. " +
                            "Энергосбережение Android иногда задерживает будильники.",
                            color = ScTextSecondary,
                            style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
            item { NativeSectionTitle("Безопасность и маршруты") }''')

print("SecureConnect session timer installed and expiry checks enabled")
