#!/usr/bin/env python3
"""Phase-1 Vipineshka brand palette on the REAL SecureConnect application UI."""
from pathlib import Path
import sys

if len(sys.argv) != 2:
    raise SystemExit('usage: apply_brand_palette.py <SecureConnect source root>')
root = Path(sys.argv[1]).resolve()

def patch(relative, replacements):
    p = root / 'app/src/main/java/com/secureconnect/app' / relative
    data = p.read_text(encoding='utf-8')
    for old, new in replacements:
        if new in data:
            continue
        if data.count(old) != 1:
            raise SystemExit(f'Patch anchor missing or ambiguous: {relative}: {old[:50]}')
        data = data.replace(old, new, 1)
    p.write_text(data, encoding='utf-8')

palette = {
 'ScBackground': ('0xFF0C1017', '0xFF050917'),
 'ScSurface': ('0xFF141B26', '0xFF0D1530'),
 'ScCard': ('0xFF1C2532', '0xFF141D38'),
 'ScCardSelected': ('0xFF273545', '0xFF30215B'),
 'ScPrimary': ('0xFFC6D3E0', '0xFF9B60FF'),
 'ScPrimaryVariant': ('0xFF526A7C', '0xFF7547DF'),
 'ScPrimarySoft': ('0xFF263746', '0xFF241645'),
 'ScOnPrimary': ('0xFF14202C', '0xFFFFFFFF'),
 'ScTextPrimary': ('0xFFF3F6FA', '0xFFF7F5FF'),
 'ScTextSecondary': ('0xFF97A5B6', '0xFFADB0D3'),
 'ScSuccess': ('0xFF79DDB8', '0xFF10E6CC'),
 'ScSuccessSoft': ('0xFF1E493B', '0xFF0E4A49'),
 'ScWarning': ('0xFFF2C074', '0xFFFFC56A'),
 'ScError': ('0xFFFF7886', '0xFFFF637C'),
 'ScBorder': ('0xFF303A49', '0xFF343A66')
}
patch('ui/theme/Color.kt', [(f'val {name} = Color({before})', f'val {name} = Color({after})') for name,(before,after) in palette.items()])
patch('ui/screens/home/HomeScreen.kt', [
 ('Text("S", style = MaterialTheme.typography.titleMedium, color = Color(0xFF14202B))',
  'Text("♛", style = MaterialTheme.typography.titleMedium, color = Color(0xFFF5EEFF))'),
 ('"SecureConnect",\n                    style = MaterialTheme.typography.titleMedium',
  '"vipineshka vpn",\n                    style = MaterialTheme.typography.titleMedium'),
 ('listOf(Color(0xFF293D4A), Color(0xFF151F2A), Color(0xFF0C1017))',
  'listOf(Color(0xFF17112E), Color(0xFF090E26), Color(0xFF040815))'),
 ('listOf(Color(0xFFD9E4ED), Color(0xFF879CAF))',
  'listOf(Color(0xFFAF73FF), Color(0xFF5B2BD9))'),
 ('listOf(Color(0xFF242F3E), Color(0xFF181F2C))',
  'listOf(Color(0xFF1B2045), Color(0xFF10172E))'),
 ('Color(0xFF374453), panelShape', 'Color(0xFF373B6B), panelShape'),
 ('"VPN активен"', '"Подключено"'),
 ('"VPN выключен"', '"Не подключен"')
])
patch('ui/components/ConnectButton.kt', [
 ('Color(0xFF5A4835)', 'Color(0xFF74511D)'),
 ('Color(0xFF39765F)', 'Color(0xFF137A70)'),
 ('Color(0xFF435565)', 'Color(0xFF5624B4)'),
 ('Color(0xFF172431)', 'Color(0xFF0D1331)')
])
print('Vipineshka real-app palette patch: ok')
