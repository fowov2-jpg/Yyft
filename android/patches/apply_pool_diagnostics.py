#!/usr/bin/env python3
"""Expose why the locally proven 21-route pool is empty; never fabricate qualification."""
from pathlib import Path
import sys

if len(sys.argv) != 2:
    raise SystemExit("usage: apply_pool_diagnostics.py <SecureConnect source root>")
root = Path(sys.argv[1]).resolve()
path = root / "app/src/main/java/com/secureconnect/app/viewmodel/VpnDiagnosticReporter.kt"
source = path.read_text(encoding="utf-8")
marker = '            appendLine("Verified pool diagnosis (local history; cloud hints are not proofs): " +'
anchor = '            appendLine("Saved working history: ${WorkingServerStore.savedRecords(app).size}/${com.secureconnect.app.vpn.WorkingPoolPolicy.MAX_HISTORY}")'
if marker not in source:
    if source.count(anchor) != 1:
        raise SystemExit("expected unique Verified pool history anchor not found")
    inserted = '''            val savedPool = WorkingServerStore.savedRecords(app)
            val poolNowMs = System.currentTimeMillis()
            val eligiblePool = savedPool.count { WorkingPoolPolicy.eligible(it.server) }
            val youtubeProofs = savedPool.count { it.youtubeVerifiedAtMs > 0L }
            val speedProofs = savedPool.count { it.speedVerifiedAtMs > 0L }
            val freshSpeedProofs = savedPool.count {
                it.speedVerifiedAtMs > 0L &&
                    poolNowMs - it.speedVerifiedAtMs in 0L..VpnSpeedPolicy.QUALITY_FRESHNESS_MS
            }
            val measuredSpeedPass = savedPool.count {
                VpnSpeedPolicy.classify(it.verifiedDownloadMbps, it.verifiedUploadMbps) ==
                    VpnSpeedPolicy.Verdict.PASS
            }
            val tlsRejected = savedPool.count { TlsRiskStore.isRisky(app, it.server.id) }
            val failedHealth = savedPool.count { it.failures > 0 }
            appendLine("Verified pool diagnosis (local history; cloud hints are not proofs): " +
                "saved=${savedPool.size}, eligible=$eligiblePool, youtube=$youtubeProofs, " +
                "speed=$speedProofs, speedFresh=$freshSpeedProofs, speed5_1=$measuredSpeedPass, " +
                "tlsRisk=$tlsRejected, failedHealth=$failedHealth")
            if (data.readyWorkingCount == 0) {
                appendLine("Pool next step: inspect local Xray/YouTube/speed proof failures and scanner status; " +
                    "the GitHub feed cannot certify local VPN usability")
            }
'''
    source = source.replace(anchor, anchor + "\n" + inserted.rstrip("\n"))
    path.write_text(source, encoding="utf-8")
print("Verified pool diagnostic patch: ok")
