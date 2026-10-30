#!/usr/bin/env python3
"""Add independent HTTPS SOCKS check after TLS-stage failures."""
from pathlib import Path
import sys

if len(sys.argv) != 2: raise SystemExit("usage: apply_health_fallback.py <root>")
root=Path(sys.argv[1]).resolve() / "app/src"
src=root/"main/java/com/secureconnect/app/vpn"
tests=root/"test/java/com/secureconnect/app/vpn"
tests.mkdir(parents=True, exist_ok=True)

pure='''package com.secureconnect.app.vpn

/** Three-provider health probe: avoids false failure if a particular
 * control HTTPS site is unavailable, without weakening certificate checks.
 */
internal object IndependentHttpsPolicy {
    fun shouldTryThird(a: String, b: String, aMs: Int?, bMs: Int?): Boolean =
        (aMs != null || bMs != null) &&
        (a == "tls" || a == "http" || b == "tls" || b == "http")
    fun shouldTryQuickThird(stage: String, socksMs: Int?): Boolean =
        socksMs != null && (stage == "tls" || stage == "http")
}
'''
policy=src/"IndependentHttpsPolicy.kt"
if policy.exists() and policy.read_text(encoding="utf-8") != pure:
    raise SystemExit("Unexpected policy file")
policy.write_text(pure, encoding="utf-8")

p=src/"XrayHealthChecker.kt"
s=p.read_text(encoding="utf-8")
def replace_unique(old,new):
    global s
    if new in s: return
    if s.count(old) != 1: raise SystemExit("Missing/duplicate source anchor: "+old[:80])
    s=s.replace(old,new,1)

replace_unique('''        Endpoint("cp.cloudflare.com", 443, "/generate_204")
''','''        Endpoint("cp.cloudflare.com", 443, "/generate_204"),
        // A different HTTPS provider; still accessed exclusively via Xray SOCKS.
        Endpoint("www.apple.com", 443, "/library/test/success.html")
''')
replace_unique('''        val probe = probeHttps(endpoint, ProbeControl(), ioTimeoutMs)
        return QuickResult(''', '''        val initial = probeHttps(endpoint, ProbeControl(), ioTimeoutMs)
        val probe = if (!initial.passed &&
            IndependentHttpsPolicy.shouldTryQuickThird(initial.stage, initial.socksMs)) {
            val third = probeHttps(HTTPS_TARGETS[2], ProbeControl(), ioTimeoutMs)
            if (third.passed) third else initial
        } else initial
        return QuickResult(''')
old='''        return listOf(
            primary,
            alternate ?: HttpsProbe(
                endpoint = HTTPS_TARGETS[1],
                socksMs = alternateControl.socksMs,
                totalMs = null,
                httpCode = null,
                stage = alternateControl.stage,
                error = "alternate wait budget $'''+'''{waitBudgetMs}ms exceeded"
            )
        )'''
new='''        val second = alternate ?: HttpsProbe(
            endpoint = HTTPS_TARGETS[1],
            socksMs = alternateControl.socksMs,
            totalMs = null,
            httpCode = null,
            stage = alternateControl.stage,
            error = "alternate wait budget $'''+'''{waitBudgetMs}ms exceeded"
        )
        // Two blocked control sites are inconclusive when remote SOCKS CONNECT
        // worked; validate a different origin with full TLS hostname checking.
        if (!primary.passed && !second.passed &&
            IndependentHttpsPolicy.shouldTryThird(primary.stage, second.stage,
                primary.socksMs, second.socksMs)) {
            return listOf(primary, second, probeHttps(HTTPS_TARGETS[2],
                ProbeControl(), ioTimeoutMs))
        }
        return listOf(primary, second)'''
replace_unique(old,new)
p.write_text(s,encoding="utf-8")

test=tests/"IndependentHttpsPolicyTest.kt"
unit='''package com.secureconnect.app.vpn
import org.junit.Assert.*
import org.junit.Test

class IndependentHttpsPolicyTest {
    @Test fun thirdOnlyAfterRemoteSocks() {
        assertTrue(IndependentHttpsPolicy.shouldTryThird("tls","http",30,40))
        assertTrue(IndependentHttpsPolicy.shouldTryThird("tls","socks_connect",30,null))
        assertFalse(IndependentHttpsPolicy.shouldTryThird("tls","tls",null,null))
        assertFalse(IndependentHttpsPolicy.shouldTryThird("socks_connect","socks_ready",null,null))
        assertFalse(IndependentHttpsPolicy.shouldTryThird("ok","ok",30,40))
    }
    @Test fun watchdogNeverClaimsUnreachableSocks() {
        assertTrue(IndependentHttpsPolicy.shouldTryQuickThird("tls",30))
        assertTrue(IndependentHttpsPolicy.shouldTryQuickThird("http",30))
        assertFalse(IndependentHttpsPolicy.shouldTryQuickThird("tls",null))
        assertFalse(IndependentHttpsPolicy.shouldTryQuickThird("ok",30))
    }
}
'''
if test.exists() and test.read_text(encoding="utf-8") != unit:
    raise SystemExit("Unexpected policy test")
test.write_text(unit,encoding="utf-8")
print("Independent HTTPS fallback patch: applied")
