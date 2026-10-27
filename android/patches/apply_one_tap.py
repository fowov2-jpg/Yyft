#!/usr/bin/env python3
"""Apply SecureConnect 2.4.8 automatic public candidate discovery to unpacked 2.4.7."""
from pathlib import Path
import shutil
import sys

root = Path(sys.argv[1]).resolve()
scanner = root / "app/src/main/java/com/secureconnect/app/vpn/ServerScanner.kt"
target = root / "app/src/main/java/com/secureconnect/app/vpn/PublicCandidateFeed.kt"
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
# Deterministic Android JVM regression tests: no emulator and no third-party VPN traffic.
regression = root / "app/src/test/java/com/secureconnect/app/viewmodel/RecoveryFlowRegressionTest.kt"
regression.parent.mkdir(parents=True, exist_ok=True)
shutil.copyfile(Path(__file__).with_name("RecoveryFlowRegressionTest.kt"), regression)

body = gradle.read_text(encoding="utf-8")
assert 'versionName = "2.4.7"' in body and 'versionCode = 253' in body
gradle.write_text(body.replace('versionCode = 253','versionCode = 254')
    .replace('versionName = "2.4.7"','versionName = "2.4.8"'), encoding="utf-8")
print("SecureConnect 2.4.8 one-tap patch applied")
