#!/usr/bin/env python3
"""Bounded empty-pool recovery under moderate native Xray PSS load.

Keeps all Android trim, low-RAM, Java heap and TLS safety gates. Does not
mark servers verified without real local checks.
"""
from pathlib import Path
import sys

if len(sys.argv) != 2:
    raise SystemExit("usage: apply_zero_pool_rescue.py <SecureConnect project root>")
root = Path(sys.argv[1])
base = root / "app/src/main/java/com/secureconnect/app"

def insert(path, old, new):
    data = path.read_text(encoding="utf-8")
    if new in data: return
    if data.count(old) != 1:
        raise SystemExit(f"Missing or duplicate anchor in {path}: {old[:85]}")
    path.write_text(data.replace(old, new, 1), encoding="utf-8")

policy = base / "util/ZeroPoolRescuePolicy.kt"
source = '''package com.secureconnect.app.util

/** One zero-reserve probe during existing limited refill windows. */
internal object ZeroPoolRescuePolicy {
    const val SOFT_PSS_BYTES = 384L * 1024L * 1024L
    const val RESCUE_PSS_CEILING_BYTES = 448L * 1024L * 1024L
    const val PROBE_INTERVAL_MS = 60_000L

    fun canStart(
        connected: Boolean, readyRoutes: Int, activeProbes: Int,
        nowMs: Long, nextProbeAtMs: Long,
        pssBytes: Long, heapUsedBytes: Long, heapMaxBytes: Long,
        trimBackoffActive: Boolean, lowRam: Boolean
    ): Boolean =
        connected && readyRoutes == 0 && activeProbes == 0 &&
            nowMs >= nextProbeAtMs &&
            pssBytes in SOFT_PSS_BYTES until RESCUE_PSS_CEILING_BYTES &&
            heapMaxBytes > 0L && heapUsedBytes >= 0L &&
            heapUsedBytes <= heapMaxBytes / 2L &&
            !trimBackoffActive && !lowRam
}
'''
if policy.exists() and policy.read_text(encoding="utf-8") != source:
    raise SystemExit("Unexpected existing ZeroPoolRescuePolicy.kt")
policy.write_text(source, encoding="utf-8")

governor = base / "util/ResourceGovernor.kt"
anchor = '    fun isMemoryPressured(context: Context? = null): Boolean {'
method = '''    /** Exception for exactly one probe when native PSS, not Android or Java
     * memory pressure, has blocked all replenishment of an empty pool.
     */
    fun mayRunOneZeroPoolProbe(
        context: Context, readyRoutes: Int, activeProbes: Int,
        nowMs: Long, nextProbeAtMs: Long
    ): Boolean {
        val am = context.getSystemService(ActivityManager::class.java)
        val runtime = Runtime.getRuntime()
        return ZeroPoolRescuePolicy.canStart(
            connected = true, readyRoutes = readyRoutes, activeProbes = activeProbes,
            nowMs = nowMs, nextProbeAtMs = nextProbeAtMs,
            pssBytes = processPssBytes(),
            heapUsedBytes = runtime.totalMemory() - runtime.freeMemory(),
            heapMaxBytes = runtime.maxMemory(),
            trimBackoffActive = System.currentTimeMillis() < pressureUntilMs.get(),
            lowRam = am?.isLowRamDevice ?: true
        )
    }

'''
insert(governor, anchor, method + anchor)

scanner = base / "vpn/ServerScanner.kt"
insert(scanner,
    "        var lastUnderfilledAuditAtMs = 0L\n",
    "        var lastUnderfilledAuditAtMs = 0L\n        var nextModeratePssProbeAtMs = 0L\n")
old = '''                val pressure = ResourceGovernor.isMemoryPressured(context)
                val emergencySearch = state == VpnState.Connecting &&
                    System.currentTimeMillis() < rescueUntilMs
                if (!XrayCore.isAvailable() ||
                    (network == null || pressure ||
                        (!ReserveScanPolicy.canLaunch(state, true, false) && !emergencySearch))) {'''
new = '''                val pressure = ResourceGovernor.isMemoryPressured(context)
                val moderatePssRescue = pressure && state == VpnState.Connected &&
                    ResourceGovernor.mayRunOneZeroPoolProbe(
                        context, readyCount, inFlight.size,
                        System.currentTimeMillis(), nextModeratePssProbeAtMs)
                val emergencySearch = state == VpnState.Connecting &&
                    System.currentTimeMillis() < rescueUntilMs
                if (!XrayCore.isAvailable() ||
                    (network == null || (pressure && !moderatePssRescue) ||
                        (!ReserveScanPolicy.canLaunch(state, true, false) && !emergencySearch))) {'''
insert(scanner, old, new)
old = '''                due.filter { TlsRiskStore.eligibleForAutomaticUse(context, it.id) }
                    .distinctBy { it.host.lowercase(java.util.Locale.ROOT) }.take((workers - inFlight.size).coerceAtLeast(0)).forEach { candidate ->'''
new = '''                val slotCount = if (moderatePssRescue) 1 else (workers - inFlight.size).coerceAtLeast(0)
                val toLaunch = due.filter { TlsRiskStore.eligibleForAutomaticUse(context, it.id) }
                    .distinctBy { it.host.lowercase(java.util.Locale.ROOT) }.take(slotCount)
                if (moderatePssRescue && toLaunch.isNotEmpty()) {
                    nextModeratePssProbeAtMs = System.currentTimeMillis() +
                        com.secureconnect.app.util.ZeroPoolRescuePolicy.PROBE_INTERVAL_MS
                    _status.value = Status(true,
                        "Ограниченный поиск при высокой PSS · 1 проверка/минуту · без ослабления TLS", checked)
                }
                toLaunch.forEach { candidate ->'''
insert(scanner, old, new)

test = root / "app/src/test/java/com/secureconnect/app/util/ZeroPoolRescuePolicyTest.kt"
test.parent.mkdir(parents=True, exist_ok=True)
test_code = '''package com.secureconnect.app.util

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ZeroPoolRescuePolicyTest {
    private fun can(
        connected: Boolean = true, ready: Int = 0, active: Int = 0,
        now: Long = 100_000L, next: Long = 0L,
        pss: Long = 441L * 1024 * 1024,
        used: Long = 60L * 1024 * 1024, max: Long = 256L * 1024 * 1024,
        trim: Boolean = false, lowRam: Boolean = false
    ) = ZeroPoolRescuePolicy.canStart(connected, ready, active, now, next,
        pss, used, max, trim, lowRam)

    @Test fun singleProbeForReportedPss() {
        assertTrue(can())
        assertFalse(can(active = 1))
        assertFalse(can(next = 160_000L))
        assertTrue(can(now = 160_000L, next = 160_000L))
    }

    @Test fun respectsAllHardSafetyLimits() {
        assertFalse(can(connected = false))
        assertFalse(can(ready = 1))
        assertFalse(can(trim = true))
        assertFalse(can(lowRam = true))
        assertFalse(can(pss = 448L * 1024 * 1024))
        assertFalse(can(pss = 384L * 1024 * 1024 - 1))
        assertFalse(can(used = 130L * 1024 * 1024))
        assertFalse(can(max = 0L))
    }
}
'''
if test.exists() and test.read_text(encoding="utf-8") != test_code:
    raise SystemExit("Unexpected existing rescue test")
test.write_text(test_code, encoding="utf-8")
print("Zero pool rescue: applied")
