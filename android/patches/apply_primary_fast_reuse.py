#!/usr/bin/env python3
"""Reuse recent independently HTTPS-proven primaries; preserve mandatory live TLS."""
from pathlib import Path
import sys
import shutil

if len(sys.argv) != 2:
    raise SystemExit("usage: apply_primary_fast_reuse.py <SecureConnect project>")
root = Path(sys.argv[1]).resolve()
src = root / "app/src"
base = src / "main/java/com/secureconnect/app"
repo = Path(__file__).resolve().parent / "primary_fast_reuse"
target = base / "vpn/PrimaryRouteHistory.kt"
if target.exists() and target.read_bytes() != (repo / target.name).read_bytes():
    raise SystemExit("Conflicting PrimaryRouteHistory in project")
shutil.copyfile(repo / target.name, target)
unit = src / "test/java/com/secureconnect/app/vpn/PrimaryRouteHistoryTest.kt"
unit.parent.mkdir(parents=True, exist_ok=True)
shutil.copyfile(repo / unit.name, unit)

def replace(file, old, new):
    p = base / file
    s = p.read_text(encoding="utf-8")
    if new in s:
        return
    if s.count(old) != 1:
        raise SystemExit("Missing or ambiguous anchor in " + file + ": " + old[:85])
    p.write_text(s.replace(old, new, 1), encoding="utf-8")

vm = "viewmodel/MainViewModel.kt"
replace(vm,
    "import com.secureconnect.app.vpn.OpenAiTlsPolicy\n",
    "import com.secureconnect.app.vpn.OpenAiTlsPolicy\n"
    "import com.secureconnect.app.vpn.PrimaryRouteHistory\n")
replace(vm,
    "recentlyConnectedIds = ConnectionHistoryStore.recentIds(ctx),",
    "recentlyConnectedIds = PrimaryRouteHistory.recentIds(ctx, ServerStore.loadCached(ctx)) +\n"
    "                ConnectionHistoryStore.recentIds(ctx),")
replace(vm,
    "records, history, ConnectionHistoryStore.recentIds(ctx), catalog,",
    "records, history,\n"
    "            PrimaryRouteHistory.recentIds(ctx, catalog) + ConnectionHistoryStore.recentIds(ctx), catalog,")
replace(vm,
    "if (riskApprovalId != candidate.id) {\n                val tls =",
    """// A live certificate-verified Xray HTTPS success on the IDENTICAL
            // outbound is remembered for 24 h. Avoid a redundant isolated
            // native Xray preflight on next start: the mandatory active-core
            // certificate-validated SOCKS HTTPS probe BELOW still gates Connected.
            if (riskApprovalId != candidate.id && !PrimaryRouteHistory.isRecent(ctx, candidate)) {
                val tls =""")
replace(vm,
    "ConnectionHistoryStore.recordConnected(ctx, selected.id)",
    "ConnectionHistoryStore.recordConnected(ctx, selected.id)\n"
    "                        PrimaryRouteHistory.recordValidated(ctx, selected)")

report = "viewmodel/VpnDiagnosticReporter.kt"
replace(report,
    'appendLine("Saved working history: ${WorkingServerStore.savedRecords(app).size}/${com.secureconnect.app.vpn.WorkingPoolPolicy.MAX_HISTORY}")',
    'appendLine("Saved working history (strict reserves): ${WorkingServerStore.savedRecords(app).size}/${com.secureconnect.app.vpn.WorkingPoolPolicy.MAX_HISTORY}")\n'
    '            appendLine("Recent HTTPS-confirmed primary routes: ${com.secureconnect.app.vpn.PrimaryRouteHistory.read(app).size}")\n'
    '            appendLine("Selected primary previously HTTPS-proven: ${data.selectedServer?.let { com.secureconnect.app.vpn.PrimaryRouteHistory.isRecent(app, it) } == true}")')

print("Installed recent config-fingerprinted primary fast reuse; live TLS still mandatory.")
