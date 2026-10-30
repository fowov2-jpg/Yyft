#!/usr/bin/env python3
"""Offline fail-closed policy audit of the fully PATCHED Android source.

This is a static gate, not malware scanning, Play Protect certification,
or a live VpnService/TUN test.
"""
from __future__ import annotations
import json
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET

ANDROID = "{http://schemas.android.com/apk/res/android}"

def run(root: Path, workflow: Path) -> dict:
    checks, warnings = {}, []
    def require(name: str, ok: bool):
        checks[name] = bool(ok)

    app = root / "app"
    manifest = ET.parse(app / "src/main/AndroidManifest.xml").getroot()
    application = manifest.find("application")
    require("android_backup_disabled", application is not None and
            application.get(ANDROID + "allowBackup") == "false")
    require("no_cleartext_override", application is not None and
            application.get(ANDROID + "usesCleartextTraffic") != "true")
    components = {}
    if application is not None:
        for tag in ("activity", "service", "receiver", "provider"):
            for element in application.findall(tag):
                components[element.get(ANDROID + "name")] = element
    vpn = components.get(".vpn.XrayVpnService")
    scanner = components.get(".ServerScanService")
    receiver = components.get(".SessionExpiryReceiver")
    require("vpn_service_protected",
            vpn is not None and vpn.get(ANDROID + "exported") == "false" and
            vpn.get(ANDROID + "permission") == "android.permission.BIND_VPN_SERVICE")
    require("scanner_service_private",
            scanner is not None and scanner.get(ANDROID + "exported") == "false")
    require("timer_receiver_private",
            receiver is not None and receiver.get(ANDROID + "exported") == "false")
    used_permissions = {p.get(ANDROID + "name") for p in manifest.findall("uses-permission")}
    queries = manifest.find("queries")
    queried = {p.get(ANDROID + "name") for p in queries.findall("package")} if queries is not None else set()
    catalogue_text = ((app / "src/main/java/com/secureconnect/app/vpn/AppRoutingPolicy.kt").read_text(encoding="utf-8") +
        (app / "src/main/java/com/secureconnect/app/vpn/RussianAppsExpanded.kt").read_text(encoding="utf-8"))
    expected = set(re.findall(r'RussianApp\("([a-zA-Z][a-zA-Z0-9_.]+)"', catalogue_text))
    intent_covered = queries is not None and any(
        child.get(ANDROID + "name") == "android.intent.action.MAIN"
        for q in queries.findall("intent") for child in q.findall("action"))
    require("package_visibility_limited_to_launcher_and_curated_presets",
            "android.permission.QUERY_ALL_PACKAGES" not in used_permissions and
            len(expected) == 125 and queried == expected and intent_covered)
    banned = {"READ_SMS", "READ_CONTACTS", "RECORD_AUDIO", "CAMERA",
              "REQUEST_INSTALL_PACKAGES", "SYSTEM_ALERT_WINDOW"}
    require("no_unapproved_sensitive_permissions",
            not any("android.permission." + suffix in used_permissions for suffix in banned))
    warnings.append("Package visibility deliberately limited: arbitrary non-launcher apps may not appear in routing UI")

    main = app / "src/main/java/com/secureconnect/app"
    timer = (main / "SessionTimer.kt").read_text(encoding="utf-8")
    policy = (main / "SessionTimerPolicy.kt").read_text(encoding="utf-8")
    run_ctrl = (main / "AppRunController.kt").read_text(encoding="utf-8")
    vpn_source = (main / "vpn/XrayVpnService.kt").read_text(encoding="utf-8")
    scanner_source = (main / "ServerScanService.kt").read_text(encoding="utf-8")
    cloud = (main / "vpn/PublicCandidateFeed.kt").read_text(encoding="utf-8")
    allowlist = (main / "vpn/PublicCandidateSourcePolicy.kt").read_text(encoding="utf-8")
    require("cloud_feed_enforces_explicit_source_allowlist",
            "PublicCandidateSourcePolicy.nameFor(" in cloud and
            '"telega_ru" -> "TelegaVPN/free-vpn-keys"' in allowlist and
            "else -> null" in allowlist)
    require("timer_has_active_vpn_choice_fix",
            "SessionTimerPolicy.startOnChoice(" in timer and
            "XrayVpnService.hasLiveTunnel()" in timer and
            "fun startOnChoice(" in policy)
    require("timer_persists_deadline_and_alarms",
            "putLong(WALL_DEADLINE" in timer and
            "putLong(ELAPSED_DEADLINE" in timer and
            "setAndAllowWhileIdle(" in timer)
    require("timer_stops_both_services",
            "AppRunController.closed(context)" in timer and
            "ServerScanner.stopAll()" in run_ctrl and
            "stopLiveForTaskRemoval()" in run_ctrl)
    home = (main / "ui/screens/home/HomeScreen.kt").read_text(encoding="utf-8")
    countdown = (main / "ui/screens/home/SessionCountdown.kt").read_text(encoding="utf-8")
    carrier = (main / "ui/screens/settings/CarrierNetworkDiagnosticsCard.kt").read_text(encoding="utf-8")
    carrier_policy = (main / "ui/screens/settings/CarrierProbePolicy.kt").read_text(encoding="utf-8")
    carrier_settings = (main / "ui/screens/settings/PremiumScreens.kt").read_text(encoding="utf-8")
    require("carrier_diagnostics_opt_in_read_only_underlying_mobile",
            "CarrierNetworkDiagnosticsCard()" in carrier_settings and
            "TRANSPORT_CELLULAR" in carrier and "Network.openConnection" in carrier and
            "network.openConnection(URL(url))" in carrier and
            "instanceFollowRedirects = false" in carrier and
            "HttpsURLConnection" in carrier and
            "rememberCoroutineScope()" in carrier and
            "Ничего не отправляется в наш GitHub" in carrier and
            "Нельзя утверждать" in carrier_policy and
            "https://vk.com/" in carrier)
    require("home_countdown_uses_persisted_deadline_foreground_only",
            "SessionCountdown()" in home and
            "SessionTimer.remainingMs(context)" in countdown and
            "Lifecycle.State.RESUMED" in countdown and
            "delay(1_000L)" in countdown and
            "SessionTimer.startIfNeeded" not in countdown)
    require("timer_expiry_checked_in_services",
            "SessionTimer.expireIfDue(this)" in vpn_source and
            "SessionTimer.expireIfDue(this)" in scanner_source)
    require("keystore_aes_gcm",
            all(s in (main / "data/local/SensitivePrefs.kt").read_text(encoding="utf-8")
                for s in ("AndroidKeyStore", "AES/GCM/NoPadding", "KeyProperties.PURPOSE_DECRYPT")))
    # A release signing key must never be bundled in a public Android source archive.
    secret_suffixes = {".jks", ".keystore", ".p12", ".pfx"}
    private_keys = [str(p.relative_to(root)) for p in root.rglob("*")
                    if p.is_file() and (p.suffix.lower() in secret_suffixes or
                    p.name == "release.keystore")]
    require("no_private_signing_keys_in_public_source", not private_keys)
    gradle = (app / "build.gradle.kts").read_text(encoding="utf-8")
    require("native_xray_sha256_pinned",
            bool(re.search(r'val xraySha256 = "[0-9a-f]{64}"', gradle)) and
            "validateXrayAar(xrayAar)" in gradle)
    builder = (main / "vpn/XrayConfigBuilder.kt").read_text(encoding="utf-8")
    require("no_tls_insecure_outbound",
            '.put("allowInsecure"' not in builder and
            'put("allowInsecure"' not in builder)
    workflow_text = workflow.read_text(encoding="utf-8")
    upload = workflow_text.rsplit("      - name: Upload APK", 1)
    require("apk_not_uploaded_after_failed_checks",
            len(upload) == 2 and
            "if: success()" in upload[1].split("      - ", 1)[0] and
            "if-no-files-found: error" in upload[1])
    require("android_lint_required_before_apk_publish",
            ":app:lintDebug" in workflow_text and
            workflow_text.index(":app:lintDebug") < workflow_text.index("      - name: Upload APK"))
    require("android_unit_tests_required",
            ":app:testDebugUnitTest" in workflow_text and
            "Audit debug APK permissions" in workflow_text)
    warnings.append("Debug signing and external public VPN operators: Play Protect verdict remains unknown")
    warnings.append("Real Xiaomi VPN/TUN, Doze timer precision and operator-network reachability are not simulated")
    return {
        "schema": 1,
        "result": "pass" if all(checks.values()) else "fail",
        "checks": checks,
        "warnings": warnings,
    }

def main() -> int:
    if len(sys.argv) != 3:
        print("usage: audit.py <patched-android-source-root> <workflow-yml>", file=sys.stderr)
        return 2
    try:
        report = run(Path(sys.argv[1]), Path(sys.argv[2]))
    except (OSError, ET.ParseError, ValueError) as exc:
        print("AUDIT ERROR:", type(exc).__name__, str(exc), file=sys.stderr)
        return 2
    output = Path("security_audit/audit-result.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    for label, good in report["checks"].items():
        print(("PASS" if good else "FAIL"), label)
    for warning in report["warnings"]:
        print("REVIEW", warning)
    print("audit result:", report["result"], "checks:", len(report["checks"]))
    return 0 if report["result"] == "pass" else 1

if __name__ == "__main__":
    raise SystemExit(main())
