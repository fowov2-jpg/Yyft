#!/usr/bin/env python3
"""Drop redundant isolated-Xray TLS preflight in AUTO only, preserving security:
the LIVE HTTPS+cert validation still gates Connected; a certificate violation
on either HTTPS health target marks route TLS-risk and requires explicit consent.
"""
from pathlib import Path
import shutil
import sys

if len(sys.argv) != 2:
    raise SystemExit("usage: apply_direct_https_bootstrap.py <SecureConnect root>")
root = Path(sys.argv[1]).resolve()
base = root / "app/src/main/java/com/secureconnect/app"
src = Path(__file__).resolve().parent / "direct_https_bootstrap"
target = base / "vpn/TlsBootstrapPolicy.kt"
if target.exists() and target.read_bytes() != (src/target.name).read_bytes():
    raise SystemExit("Conflicting TLS bootstrap policy")
shutil.copyfile(src/target.name, target)
test = root / "app/src/test/java/com/secureconnect/app/vpn/TlsBootstrapPolicyTest.kt"
test.parent.mkdir(parents=True,exist_ok=True)
shutil.copyfile(src/test.name, test)

def patch(rel, old, new):
    path = base / rel
    text = path.read_text(encoding="utf-8")
    if new in text:
        return
    if text.count(old) != 1:
        raise SystemExit("Expected exactly one patch anchor in " + rel + ": " + old[:100])
    path.write_text(text.replace(old,new,1),encoding="utf-8")

vm = "viewmodel/MainViewModel.kt"
patch(vm,
    "import com.secureconnect.app.vpn.PrimaryRouteHistory\n",
    "import com.secureconnect.app.vpn.PrimaryRouteHistory\n"
    "import com.secureconnect.app.vpn.TlsBootstrapPolicy\n")
patch(vm,
    "if (riskApprovalId != candidate.id && !PrimaryRouteHistory.isRecent(ctx, candidate)) {",
    """if (TlsBootstrapPolicy.needsStandalonePreflight(
                    automaticMode = _connectionMode.value == ConnectionMode.AUTO,
                    recentlyProvenIdenticalConfig = PrimaryRouteHistory.isRecent(ctx, candidate),
                    riskApprovedForSession = riskApprovalId == candidate.id
                )) {""")
patch(vm,
    'lastError = health?.error ?: "Не удалось подтвердить реальный HTTPS-трафик"\n'
    '                    healthLedger.recordFailure(candidate.id, health?.failureStage ?: "health_unknown")',
    '''lastError = if (health?.failureStage == "tls_certificate") {
                        // Trusted Android TLS validation failed inside the active Xray.
                        // Never mark this route Connected, even if another CDN worked.
                        TlsRiskStore.markRisk(ctx, candidate.id)
                        "Риск подмены TLS-сертификата: автоматическое подключение к серверу запрещено"
                    } else {
                        health?.error ?: "Не удалось подтвердить реальный HTTPS-трафик"
                    }
                    healthLedger.recordFailure(candidate.id, health?.failureStage ?: "health_unknown")''')
checker = "vpn/XrayHealthChecker.kt"
patch(checker,
    'val winner = probes.firstOrNull { it.passed }',
    '''// A certificate error on either control endpoint overrides a second
                // endpoint's success. Fail closed instead of hiding TLS MITM.
                val winner = if (TlsBootstrapPolicy.hasCertificateProblem(
                        probes.map { it.stage })) null
                    else probes.firstOrNull { it.passed }''')
patch(checker,
    '                            "tls" -> "TLS через Xray не установился"',
    '                            "tls_certificate" -> "Сертификат HTTPS через Xray не доверен"\n'
    '                            "tls" -> "TLS через Xray не установился"')
patch(checker,
    '''        } catch (e: SSLException) {
            HttpsProbe(endpoint, control.socksMs, null, null, "tls", compactError(e))
''',
    '''        } catch (e: SSLException) {
            val reason = if (TlsBootstrapPolicy.isCertificateFailure(e)) {
                "tls_certificate"
            } else {
                "tls"
            }
            HttpsProbe(endpoint, control.socksMs, null, null, reason, compactError(e))
''')
patch(checker,
    '''    private fun stageRank(stage: String): Int = when (stage) {
        "http" -> 4''',
    '''    private fun stageRank(stage: String): Int = when (stage) {
        "tls_certificate" -> 5
        "http" -> 4''')

print("AUTO no longer initializes redundant isolated Xray; mandatory live TLS certificate validation and risk quarantine remain.")
