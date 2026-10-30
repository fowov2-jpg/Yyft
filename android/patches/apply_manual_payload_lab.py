#!/usr/bin/env python3
"""Install opt-in HTTP Payload lab into actual SecureConnect Android UI.

No network probing outside a manual button, no Xray config modifications,
no foreground services, no background scans, no automatic proxy switching.
"""
from pathlib import Path
import sys
import shutil

if len(sys.argv) != 2:
    raise SystemExit("usage: apply_manual_payload_lab.py <SecureConnect project root>")
root = Path(sys.argv[1]).resolve()
repo = Path(__file__).resolve().parent / "manual_payload"
base = root / "app/src/main/java/com/secureconnect/app"
testbase = root / "app/src/test/java/com/secureconnect/app/vpn"

for name in ("ManualPayloadCodec.kt", "ManualPayloadGatewayProbe.kt",
             "AutoPayloadGenerator.kt", "AutoPayloadGatewayProbe.kt"):
    target = base / "vpn" / name
    if target.exists() and target.read_bytes() != (repo/name).read_bytes():
        raise SystemExit(f"Conflicting source: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(repo/name, target)

target = base / "ui/screens/settings/ManualPayloadLabScreen.kt"
target.parent.mkdir(parents=True, exist_ok=True)
if target.exists() and target.read_bytes() != (repo/"ManualPayloadLabScreen.kt").read_bytes():
    raise SystemExit(f"Conflicting screen: {target}")
shutil.copyfile(repo/"ManualPayloadLabScreen.kt", target)

auto_screen = base / "ui/screens/settings/AutoPayloadGeneratorPanel.kt"
if auto_screen.exists() and auto_screen.read_bytes() != (repo/"AutoPayloadGeneratorPanel.kt").read_bytes():
    raise SystemExit(f"Conflicting auto-generator screen: {auto_screen}")
shutil.copyfile(repo/"AutoPayloadGeneratorPanel.kt", auto_screen)

testbase.mkdir(parents=True, exist_ok=True)
shutil.copyfile(repo/"ManualPayloadCodecTest.kt", testbase/"ManualPayloadCodecTest.kt")
shutil.copyfile(repo/"AutoPayloadGeneratorTest.kt", testbase/"AutoPayloadGeneratorTest.kt")

def patch(path, before, after):
    text = path.read_text(encoding="utf-8")
    if after in text:
        return
    if text.count(before) != 1:
        raise SystemExit(f"Missing or ambiguous anchor: {path.name} / {before[:65]}")
    path.write_text(text.replace(before, after, 1), encoding="utf-8")

navigation = base / "ui/navigation/AppNavigation.kt"
patch(navigation,
    "import com.secureconnect.app.ui.screens.settings.PremiumSettingsScreen\n",
    "import com.secureconnect.app.ui.screens.settings.PremiumSettingsScreen\n"
    "import com.secureconnect.app.ui.screens.settings.ManualPayloadLabScreen\n")
patch(navigation,
    "PremiumSettingsScreen(vm, onBack = { nav.popBackStack() })",
    "PremiumSettingsScreen(vm, onBack = { nav.popBackStack() },\n"
    "                    onPayloadLab = { nav.navigate(Screen.PayloadLab.route) })")
patch(navigation,
    '            composable(Screen.Technical.route) {',
    '            composable(Screen.PayloadLab.route) {\n'
    '                ManualPayloadLabScreen(onBack = { nav.popBackStack() })\n'
    '            }\n'
    '            composable(Screen.Technical.route) {')

screenroutes = base / "ui/navigation/Screen.kt"
patch(screenroutes,
    '    object Technical : Screen("technical")',
    '    object PayloadLab : Screen("payload_lab")\n'
    '    object Technical : Screen("technical")')

settings = base / "ui/screens/settings/PremiumScreens.kt"
patch(settings,
    'fun PremiumSettingsScreen(vm: MainViewModel, onBack: () -> Unit) {',
    'fun PremiumSettingsScreen(vm: MainViewModel, onBack: () -> Unit,\n'
    '    onPayloadLab: () -> Unit) {')
patch(settings,
    '            item { NativeSectionTitle("Бесплатный рейтинг GitHub") }',
    '            item { NativeSectionTitle("Ручная диагностика сети") }\n'
    '            item {\n'
    '                NativeGroup {\n'
    '                    NativeActionRow(\n'
    '                        title = "HTTP Payload · вручную",\n'
    '                        subtitle = "Редактор [crlf] и один тест своего шлюза; VPN не изменяется",\n'
    '                        onClick = onPayloadLab\n'
    '                    )\n'
    '                }\n'
    '            }\n'
    '            item { NativeSectionTitle("Бесплатный рейтинг GitHub") }')
print("Manual HTTP payload lab + bounded combination search installed; no Xray changes")
