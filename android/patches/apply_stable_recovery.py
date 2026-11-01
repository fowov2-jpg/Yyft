#!/usr/bin/env python3
"""Stable SecureConnect recovery: encrypted HTTPS-proven Xray routes, no new scanner."""
from pathlib import Path
import shutil
import sys

if len(sys.argv) != 2:
    raise SystemExit("usage: apply_stable_recovery.py <SecureConnect root>")
root = Path(sys.argv[1]).resolve()
base = root / "app/src/main/java/com/secureconnect/app"
tests = root / "app/src/test/java/com/secureconnect/app/vpn"
repo = Path(__file__).resolve().parent / "stable_recovery"
for name, path in (
    ("SuccessfulRouteCachePolicy.kt", base / "vpn/SuccessfulRouteCachePolicy.kt"),
    ("SuccessfulRouteCache.kt", base / "data/local/SuccessfulRouteCache.kt"),
    ("SuccessfulRouteCachePolicyTest.kt", tests / "SuccessfulRouteCachePolicyTest.kt"),
):
    path.parent.mkdir(parents=True, exist_ok=True)
    expected = (repo / name).read_bytes()
    if path.exists() and path.read_bytes() != expected:
        raise SystemExit("Conflicting source: " + str(path))
    path.write_bytes(expected)

def swap(rel, old, new):
    path = base / rel
    text = path.read_text(encoding="utf-8")
    if new in text:
        return
    if text.count(old) != 1:
        raise SystemExit("Missing or ambiguous anchor in " + rel + ": " + old[:85])
    path.write_text(text.replace(old, new, 1), encoding="utf-8")

vm = "viewmodel/MainViewModel.kt"
swap(vm,
    "import com.secureconnect.app.data.local.ConnectionHistoryStore\n",
    "import com.secureconnect.app.data.local.ConnectionHistoryStore\n"
    "import com.secureconnect.app.data.local.SuccessfulRouteCache\n"
    "import com.secureconnect.app.vpn.SuccessfulRouteCachePolicy\n")
swap(vm,
    '''        if (compatible.isEmpty()) {
            val message = "В каталоге пока нет совместимых конфигураций. Проверьте источники и сеть."''',
    '''        // Only configs that previously passed live Xray HTTPS and Android TLS.
        // Re-verify on every reuse. No cached route is already Connected.
        val cachedRecovery = if (_connectionMode.value == ConnectionMode.AUTO && riskApprovalId == null) {
            SuccessfulRouteCache.candidates(ctx) { cached ->
                WorkingPoolPolicy.eligible(cached) &&
                    TlsRiskStore.eligibleForAutomaticUse(ctx, cached.id) &&
                    XrayConfigBuilder.build(cached, null) != null
            }
        } else emptyList()
        if (compatible.isEmpty() && cachedRecovery.isEmpty()) {
            val message = "Нет совместимых серверов ни в каталоге, ни в защищённом резерве восстановления."''')
swap(vm,
    '''        val maxAttempts = minOf(QuickConnectPolicy.MAX_INITIAL_ATTEMPTS, compatible.size)
        val attemptedIds = LinkedHashSet<String>()''',
    '''        val normalAttempts = minOf(QuickConnectPolicy.MAX_INITIAL_ATTEMPTS, compatible.size)
        val maxAttempts = normalAttempts + minOf(
            SuccessfulRouteCachePolicy.MAX_FALLBACK_ATTEMPTS, cachedRecovery.size)
        val attemptedIds = LinkedHashSet<String>()
        val attemptedRawConfigs = LinkedHashSet<String>()''')
swap(vm,
    '''            val remaining = compatible.filterNot { it.id in attemptedIds }
            if (remaining.isEmpty()) break

            val rankedRemaining = healthLedger.rank(remaining)
            // First connect to the highest-priority known endpoint, not to an
            // arbitrary selected catalogue card. Later attempts adapt to failures.
            val explicitPrimary = if (index == 0) remaining.firstOrNull() else null
            val candidate = explicitPrimary ?: ServerSelector.chooseAdaptive(
                ranked = rankedRemaining,
                sourceFailures = sourceFailures,
                familyFailures = familyFailures,
                isCoolingDown = { healthLedger.isCoolingDown(it.id) },
                hasSuccessfulHistory = { healthLedger.hasSuccessfulHistory(it.id) },
                isWorking = { it.id in workingIds },
                knownLatencyMs = {
                    workingLatency[it.id]
                        ?: it.ping.takeIf { ping -> ping > 0 }
                        ?: healthLedger.ewmaMs(it.id)
                }
            ) ?: break
            attemptedIds += candidate.id''',
    '''            val isRecovery = index >= normalAttempts
            val remaining = if (!isRecovery) compatible.filterNot { it.id in attemptedIds }
                else emptyList()
            val explicitPrimary = if (index == 0 && !isRecovery) remaining.firstOrNull()
                else null
            val candidate = if (isRecovery) {
                cachedRecovery.firstOrNull { it.rawLink !in attemptedRawConfigs &&
                    TlsRiskStore.eligibleForAutomaticUse(ctx, it.id) }
            } else {
                explicitPrimary ?: ServerSelector.chooseAdaptive(
                    ranked = healthLedger.rank(remaining),
                    sourceFailures = sourceFailures,
                    familyFailures = familyFailures,
                    isCoolingDown = { healthLedger.isCoolingDown(it.id) },
                    hasSuccessfulHistory = { healthLedger.hasSuccessfulHistory(it.id) },
                    isWorking = { it.id in workingIds },
                    knownLatencyMs = {
                        workingLatency[it.id]
                            ?: it.ping.takeIf { ping -> ping > 0 }
                            ?: healthLedger.ewmaMs(it.id)
                    }
                )
            } ?: break
            attemptedIds += candidate.id
            attemptedRawConfigs += candidate.rawLink
            if (isRecovery) log("INFO", "Защищённый резерв: повторная HTTPS-проверка ${index - normalAttempts + 1}")''')
swap(vm,
    '''                        PrimaryRouteHistory.recordValidated(ctx, selected)
                        // Monotonic elapsed time''',
    '''                        PrimaryRouteHistory.recordValidated(ctx, selected)
                        runCatching {
                            SuccessfulRouteCache.recordHttpsSuccess(ctx, selected)
                        }.onFailure { error ->
                            log("WARN", "Зашифрованный кэш успешного VPN недоступен: ${error.javaClass.simpleName}")
                        }
                        // Monotonic elapsed time''')
swap(vm,
    '''            rememberSessionFailure(candidate)

            // Keep the Android TUN alive between candidates.''',
    '''            rememberSessionFailure(candidate)
            // Preserve previous successes; cool down failed cached configs.
            runCatching { SuccessfulRouteCache.recordFailure(ctx, candidate) }

            // Keep the Android TUN alive between candidates.''')
swap(vm,
    '''        val selected = _selectedServer.value?.takeIf { TlsRiskStore.eligibleForAutomaticUse(ctx, it.id) }
            ?: records.firstOrNull()
            ?: history.firstOrNull() ?: catalog.firstOrNull() ?: return null''',
    '''        val recovery = SuccessfulRouteCache.candidates(ctx) { cached ->
            WorkingPoolPolicy.eligible(cached) &&
                TlsRiskStore.eligibleForAutomaticUse(ctx, cached.id) &&
                XrayConfigBuilder.build(cached, null) != null
        }
        val selected = _selectedServer.value?.takeIf { TlsRiskStore.eligibleForAutomaticUse(ctx, it.id) }
            ?: records.firstOrNull()
            ?: history.firstOrNull() ?: catalog.firstOrNull()
            ?: recovery.firstOrNull() ?: return null''')
swap(vm,
    '''            .firstOrNull { XrayConfigBuilder.build(it, null) != null }
    }

    /** Only an explicit dialog click''',
    '''            .firstOrNull { XrayConfigBuilder.build(it, null) != null }
            ?: recovery.firstOrNull()
    }

    /** Only an explicit dialog click''')
report = "viewmodel/VpnDiagnosticReporter.kt"
swap(report,
    '''            appendLine("Recent HTTPS-confirmed primary routes: ${com.secureconnect.app.vpn.PrimaryRouteHistory.read(app).size}")''',
    '''            appendLine("Recent HTTPS-confirmed primary routes: ${com.secureconnect.app.vpn.PrimaryRouteHistory.read(app).size}")
            appendLine("Encrypted successful VPN recovery cache (revalidate before use): ${com.secureconnect.app.data.local.SuccessfulRouteCache.records(app).size}/${com.secureconnect.app.vpn.SuccessfulRouteCachePolicy.MAX_SAVED}")''')
print("Stable Xray: 4 normal attempts then up to 3 encrypted HTTPS-proven recovery routes; no HTTP payload lab.")
