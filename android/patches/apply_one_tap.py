#!/usr/bin/env python3
"""Apply SecureConnect 2.4.8 automatic public candidate discovery to unpacked 2.4.7."""
from pathlib import Path
import shutil
import sys

root = Path(sys.argv[1]).resolve()
scanner = root / "app/src/main/java/com/secureconnect/app/vpn/ServerScanner.kt"
target = root / "app/src/main/java/com/secureconnect/app/vpn/PublicCandidateFeed.kt"
fallback_target = root / "app/src/main/java/com/secureconnect/app/vpn/PublicCandidateFallbackPolicy.kt"
gradle = root / "app/build.gradle.kts"
source = Path(__file__).with_name("PublicCandidateFeed.kt")

text = scanner.read_text(encoding="utf-8")

def replace(old, new):
    global text
    if old not in text:
        raise RuntimeError("Outdated Android source: missing patch anchor " + old[:70])
    text = text.replace(old, new, 1)

replace("    private var publicFeedJob: Job? = null",
        "    private var publicFeedJob: Job? = null\n    private var publicCandidatesJob: Job? = null")
replace("        if (job?.isActive == true) return",
"""        // Get checked PUBLIC share links automatically; they are unverified locally.
        if (publicCandidatesJob?.isActive != true) {
            publicCandidatesJob = scope.launch(Dispatchers.IO) {
                if (PublicCandidateFeed.refreshAndMerge(context.applicationContext)) {
                    scanWake.trySend(Unit)
                    catalogueWake.trySend(Unit)
                }
            }
        }
        if (job?.isActive == true) return""")
replace("        publicFeedJob = null\n        job?.cancel()",
        "        publicFeedJob = null\n        publicCandidatesJob?.cancel()\n        publicCandidatesJob = null\n        job?.cancel()")
replace("            publicFeedJob = null\n            job?.cancel()",
        "            publicFeedJob = null\n            publicCandidatesJob?.cancel()\n            publicCandidatesJob = null\n            job?.cancel()")
replace("                                val combined = (proven + result.servers + ServerStore.loadCached(context))",
"""                                val cloudIds = PublicCandidateFeed.recentlyVerifiedIds(context)
                                val cloud = ServerStore.loadCached(context).filter { it.id in cloudIds }
                                val combined = (proven + cloud + result.servers + ServerStore.loadCached(context))""")
# On foreground return, schedule a small refresh and otherwise keep battery sleep.
anchor = "        catalogueWake.trySend(Unit)\n        scanWake.trySend(Unit)\n    }\n\n    fun request("
replace(anchor, """        if (publicCandidatesJob?.isActive != true) {
            publicCandidatesJob = scope.launch(Dispatchers.IO) {
                if (PublicCandidateFeed.refreshAndMerge(context.applicationContext)) {
                    scanWake.trySend(Unit)
                }
            }
        }
        catalogueWake.trySend(Unit)
        scanWake.trySend(Unit)
    }

    fun request(""")
scanner.write_text(text, encoding="utf-8")
shutil.copyfile(source, target)
shutil.copyfile(Path(__file__).with_name("PublicCandidateFallbackPolicy.kt"),
                fallback_target)
shutil.copyfile(Path(__file__).with_name("PublicCandidateSourcePolicy.kt"),
                root / "app/src/main/java/com/secureconnect/app/vpn/PublicCandidateSourcePolicy.kt")
# Deterministic Android JVM regression tests: no emulator and no third-party VPN traffic.
regression = root / "app/src/test/java/com/secureconnect/app/viewmodel/RecoveryFlowRegressionTest.kt"
regression.parent.mkdir(parents=True, exist_ok=True)
shutil.copyfile(Path(__file__).with_name("RecoveryFlowRegressionTest.kt"), regression)

body = gradle.read_text(encoding="utf-8")
assert 'versionName = "2.4.7"' in body and 'versionCode = 253' in body
gradle.write_text(body.replace('versionCode = 253','versionCode = 254')
    .replace('versionName = "2.4.7"','versionName = "2.4.8"'), encoding="utf-8")
print("SecureConnect 2.4.8 one-tap patch applied")

# One-tap recovery (bounded retry waves); this is a ViewModel-lifetime policy.
vm_path = root / "app/src/main/java/com/secureconnect/app/viewmodel/MainViewModel.kt"
vm = vm_path.read_text(encoding="utf-8")
def patch_vm(old, new):
    global vm
    if vm.count(old) != 1:
        raise RuntimeError("Unexpected MainViewModel anchor: " + old[:75])
    vm = vm.replace(old, new, 1)

patch_vm("    private var connectJob: Job? = null",
"""    private var oneTapWanted = false
    private var oneTapRetryRounds = 0
    private var oneTapRetryJob: Job? = null
    private var connectJob: Job? = null""")

patch_vm("""                        autoSelection.cancel()
                        _isConnecting.value = false""",
"""                        autoSelection.cancel()
                        oneTapWanted = false
                        oneTapRetryRounds = 0
                        oneTapRetryJob?.cancel()
                        oneTapRetryJob = null
                        _isConnecting.value = false""")

patch_vm("""        // VPN is latency-sensitive. Stop subscription refresh/probing so one of""",
"""        // One button keeps requesting safe candidates after the initial quick wave.
        if (_connectionMode.value == ConnectionMode.AUTO && TlsRiskStore.currentApprovedServerId() == null) {
            oneTapWanted = true
            oneTapRetryJob?.cancel()
            oneTapRetryJob = null
        } else if (TlsRiskStore.currentApprovedServerId() != null) {
            // A one-time explicit risky TLS approval is NOT permission for unattended retries.
            oneTapWanted = false
            oneTapRetryJob?.cancel()
            oneTapRetryJob = null
        }

        // VPN is latency-sensitive. Stop subscription refresh/probing so one of""")

patch_vm("""                    connectJob = null
                    checkServers()
                }
            }
        }
    }

    private suspend fun connectInternal""",
"""                    connectJob = null
                    checkServers()
                    scheduleOneTapRetry(generation)
                }
            }
        }
    }

    private suspend fun connectInternal""")

patch_vm("""    private fun isGenerationCurrent(generation: Long): Boolean = generation == connectionGeneration""",
"""    /**
     * Continue AUTO after the four fast attempts, without a busy loop.
     * One timer and one connect job; manual STOP/mode change invalidates both.
     * The next wave reorders locally failed/cooling candidates and sees fresh feed.
     */
    private fun scheduleOneTapRetry(generation: Long) {
        if (!isGenerationCurrent(generation) ||
            !OneTapRetryPolicy.shouldContinue(
                oneTapWanted, _connectionMode.value == ConnectionMode.AUTO,
                automaticConnectSuppressed,
                _isConnected.value || VpnController.state.value == VpnState.Connected,
                vpnPermissionIntent() == null
            )) return
        val waitMs = OneTapRetryPolicy.retryDelayMs(++oneTapRetryRounds)
        oneTapRetryJob?.cancel()
        _vpnError.value = "Проверенные серверы пока не подключились. Продолжаю поиск через " +
            (waitMs / 1000L) + " с; остановить можно кнопкой «Отключить»."
        oneTapRetryJob = viewModelScope.launch {
            delay(waitMs)
            if (!isGenerationCurrent(generation) ||
                !OneTapRetryPolicy.shouldContinue(
                    oneTapWanted, _connectionMode.value == ConnectionMode.AUTO,
                    automaticConnectSuppressed,
                    _isConnected.value || VpnController.state.value == VpnState.Connected,
                    vpnPermissionIntent() == null
                )) return@launch
            checkServers() // scanner applies its own bounded refresh and sleep policy
            val next = chooseBestAutoServer() ?: chooseQuickAutoCandidate()
            if (next == null) {
                scheduleOneTapRetry(generation)
            } else {
                _selectedServer.value = next.copy(isFavorite = next.id in favoriteIds)
                selectedServerExplicit = false
                connect()
            }
        }
    }

    private fun isGenerationCurrent(generation: Long): Boolean = generation == connectionGeneration""")

patch_vm("""    fun disconnect() {
        cancelAutoSelection()""",
"""    fun disconnect() {
        cancelAutoSelection()""")

patch_vm("""        automaticConnectSuppressed = false
        autoSelection.request()""",
"""        automaticConnectSuppressed = false
        oneTapWanted = true
        oneTapRetryRounds = 0
        oneTapRetryJob?.cancel()
        oneTapRetryJob = null
        autoSelection.request()""")

patch_vm("""    fun cancelAutoSelection() {
        autoSelection.cancel()""",
"""    fun cancelAutoSelection() {
        autoSelection.cancel()
        oneTapWanted = false
        oneTapRetryRounds = 0
        oneTapRetryJob?.cancel()
        oneTapRetryJob = null""")

patch_vm("""                    reconnectJob = null
                    checkServers()
                }
            }
        }
    }

    fun toggleFavorite""",
"""                    reconnectJob = null
                    checkServers()
                    scheduleOneTapRetry(generation)
                }
            }
        }
    }

    fun toggleFavorite""")

patch_vm("""    override fun onCleared() {
        ++connectionGeneration""",
"""    override fun onCleared() {
        oneTapWanted = false
        oneTapRetryJob?.cancel()
        ++connectionGeneration""")

vm_path.write_text(vm, encoding="utf-8")
policy = root / "app/src/main/java/com/secureconnect/app/viewmodel/OneTapRetryPolicy.kt"
policy.write_text("""package com.secureconnect.app.viewmodel

/**
 * Four fast Xray/TLS attempts in each wave, then battery-bounded retry.
 * This is not a license to bypass certificate errors or the VPN kill switch.
 */
internal object OneTapRetryPolicy {
    const val MAX_ATTEMPTS_PER_WAVE = 4
    fun retryDelayMs(failedWaves: Int): Long = when (failedWaves) {
        1 -> 20_000L
        2 -> 40_000L
        3 -> 90_000L
        else -> 180_000L
    }
    fun shouldContinue(
        requested: Boolean, autoMode: Boolean, suppressed: Boolean,
        connected: Boolean, permissionGranted: Boolean
    ): Boolean = requested && autoMode && !suppressed && !connected && permissionGranted
}
""", encoding="utf-8")
print("SecureConnect one-tap bounded retry patch applied")
