#!/usr/bin/env python3
"""Respect explicit auto-connect and make one launch attempt after cache arrives.
No extra scans, timers, requests or retry storms.
"""
from pathlib import Path
import sys
if len(sys.argv)!=2: raise SystemExit("usage: apply_autostart_settings_fix.py <SecureConnect root>")
p=Path(sys.argv[1]).resolve()/"app/src/main/java/com/secureconnect/app/viewmodel/MainViewModel.kt"
s=p.read_text(encoding="utf-8")
def patch(old,new):
    global s
    if new in s: return
    if s.count(old)!=1: raise SystemExit("Missing or ambiguous anchor: "+old[:80])
    s=s.replace(old,new,1)
patch('''    private var connectionGeneration = 0L
''','''    private var connectionGeneration = 0L
    /** One opt-in launch attempt per ViewModel life; no endless retry/storm. */
    private var autoStartAttempted = false
''')
patch('''        _autoConnect.value = false
        _autoRecovery.value = true''','''        _autoConnect.value = prefs.getBoolean("auto_connect", false)
        _autoRecovery.value = true''')
patch('''        prefs.edit().putBoolean("auto_connect", false)
            .putBoolean("auto_recovery", true)''','''        prefs.edit().putBoolean("auto_recovery", true)''')
patch('''            if (canAutoConnect) {
                selectAutoServer()
            }''','''            if (canAutoConnect && !autoStartAttempted) {
                autoStartAttempted = true
                selectAutoServer()
            }''')
patch('''                if (autoSelectionPending.value) completeAutoSelection()
            }
        }
        viewModelScope.launch {
            ServerRepository.latestStatuses.collect''','''                if (autoSelectionPending.value) {
                    completeAutoSelection()
                } else if (_autoConnect.value && !autoStartAttempted &&
                    !automaticConnectSuppressed && !_isConnected.value &&
                    !_isConnecting.value && vpnPermissionIntent() == null &&
                    _servers.value.isNotEmpty()) {
                    // Cache arrived after startup; do not wait for strict 720p reserve.
                    autoStartAttempted = true
                    selectAutoServer()
                }
            }
        }
        viewModelScope.launch {
            ServerRepository.latestStatuses.collect''')
patch('''        if (v && !_isConnected.value && !_isConnecting.value && vpnPermissionIntent() == null) {
            selectAutoServer()
        }''','''        if (v && !_isConnected.value && !_isConnecting.value && vpnPermissionIntent() == null) {
            autoStartAttempted = true
            selectAutoServer()
        }''')
p.write_text(s,encoding="utf-8")
print("Auto-connect settings and cold-cache launch fix: OK")
