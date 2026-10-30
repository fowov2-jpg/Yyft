#!/usr/bin/env python3
"""Pause optional background reserve discovery while Android is thermally throttled.

Preserves the running Xray/TUN connection, health checking, kill switch and user STOP.
Does not request a wake lock or override Android thermal signals.
"""
from pathlib import Path
import sys

if len(sys.argv) != 2:
    raise SystemExit("usage: apply_thermal_safety.py <SecureConnect source root>")
root = Path(sys.argv[1]).resolve() / "app/src"
src = root / "main/java/com/secureconnect/app/vpn"
tests = root / "test/java/com/secureconnect/app/vpn"
tests.mkdir(parents=True, exist_ok=True)
policy = src / "ThermalScanPolicy.kt"
policy_text = """package com.secureconnect.app.vpn

/** Limits ONLY reserve discovery; never stops an established VPN tunnel. */
internal object ThermalScanPolicy {
    fun pauseOptionalDiscovery(
        connected: Boolean,
        apiLevel: Int,
        thermalStatus: Int,
        batterySaver: Boolean
    ): Boolean = connected && (batterySaver || (apiLevel >= 29 && thermalStatus >= 1))
}
"""
if policy.exists() and policy.read_text(encoding="utf-8") != policy_text:
    raise SystemExit("Unexpected existing ThermalScanPolicy.kt")
policy.write_text(policy_text, encoding="utf-8")

scanner = src / "ServerScanner.kt"
data = scanner.read_text(encoding="utf-8")
def replace(old, new):
    global data
    if new in data:
        return
    if data.count(old) != 1:
        raise SystemExit("Scanner anchor not unique: " + old[:85])
    data = data.replace(old, new, 1)

replace("import android.net.NetworkCapabilities\n",
        "import android.net.NetworkCapabilities\nimport android.os.Build\nimport android.os.PowerManager\n")
replace('''            try {
                if (!discoveryAllowed(context)) {''','''            try {
                val powerManager = context.getSystemService(PowerManager::class.java)
                val thermalStatus = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    powerManager?.currentThermalStatus ?: PowerManager.THERMAL_STATUS_NONE
                } else PowerManager.THERMAL_STATUS_NONE
                val thermalPause = ThermalScanPolicy.pauseOptionalDiscovery(
                    connected = VpnController.state.value == VpnState.Connected,
                    apiLevel = Build.VERSION.SDK_INT,
                    thermalStatus = thermalStatus,
                    batterySaver = powerManager?.isPowerSaveMode == true
                )
                if (thermalPause) {
                    inFlight.values.forEach { it.cancel() }
                    inFlight.clear()
                    _status.value = Status(false,
                        "Экономия батареи/температура · поиск резервов на паузе · VPN-сессия сохранена",
                        checked)
                    awaitScan(60_000L)
                    continue
                }
                if (!discoveryAllowed(context)) {''')
scanner.write_text(data, encoding="utf-8")

test = tests / "ThermalScanPolicyTest.kt"
unit = """package com.secureconnect.app.vpn

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ThermalScanPolicyTest {
    @Test fun ignoresIdleAndConnecting() {
        assertFalse(ThermalScanPolicy.pauseOptionalDiscovery(false, 36, 5, true))
    }
    @Test fun pausesAtLightOrAboveWithoutKillingVpn() {
        assertTrue(ThermalScanPolicy.pauseOptionalDiscovery(true, 36, 1, false))
        assertTrue(ThermalScanPolicy.pauseOptionalDiscovery(true, 36, 4, false))
        assertFalse(ThermalScanPolicy.pauseOptionalDiscovery(true, 36, 0, false))
    }
    @Test fun respectsBatterySaverAndLegacyApi() {
        assertTrue(ThermalScanPolicy.pauseOptionalDiscovery(true, 26, 0, true))
        assertFalse(ThermalScanPolicy.pauseOptionalDiscovery(true, 26, 4, false))
    }
}
"""
if test.exists() and test.read_text(encoding="utf-8") != unit:
    raise SystemExit("Unexpected ThermalScanPolicyTest.kt")
test.write_text(unit, encoding="utf-8")
print("Thermal safety patch: ok")
