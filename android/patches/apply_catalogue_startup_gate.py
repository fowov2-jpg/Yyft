#!/usr/bin/env python3
"""Gate first AUTO connection on real usable catalogue/recovery, display loading stage."""
from pathlib import Path
import shutil
import sys

if len(sys.argv) != 2:
    raise SystemExit('usage: apply_catalogue_startup_gate.py <SecureConnect project>')
root = Path(sys.argv[1]).resolve()
base = root / 'app/src/main/java/com/secureconnect/app'
src = Path(__file__).resolve().parent / 'catalogue_startup'
for name, destination in (
    ('CatalogueStartupPolicy.kt', base/'viewmodel/CatalogueStartupPolicy.kt'),
    ('CatalogueStartupScreen.kt', base/'ui/screens/home/CatalogueStartupScreen.kt'),
    ('CatalogueStartupPolicyTest.kt',root/'app/src/test/java/com/secureconnect/app/viewmodel/CatalogueStartupPolicyTest.kt'),
):
    destination.parent.mkdir(parents=True, exist_ok=True)
    data = (src/name).read_bytes()
    if destination.exists() and destination.read_bytes() != data:
        raise SystemExit('Conflicting source ' + str(destination))
    destination.write_bytes(data)

def patch(path, old, new):
    text = path.read_text(encoding='utf-8')
    if new in text:
        return
    if text.count(old) != 1:
        raise SystemExit('Nonunique/missing integration anchor '+path.name+' '+old[:110])
    path.write_text(text.replace(old, new, 1), encoding='utf-8')

vm = base/'viewmodel/MainViewModel.kt'
patch(vm,
    '    val catalogueStatus = ServerScanner.catalogueStatus\n',
    '''    val catalogueStatus = ServerScanner.catalogueStatus
    private val _catalogueStartup = MutableStateFlow(CatalogueStartupPolicy.State(
        CatalogueStartupPolicy.Phase.LOADING, 0, "Загружается список серверов из подписок…"))
    val catalogueStartup: StateFlow<CatalogueStartupPolicy.State> = _catalogueStartup.asStateFlow()

    /** A saved config can be reused only if it is syntactically Xray-compatible;
     * connecting still performs a fresh, certificate-checked live HTTPS probe. */
    private fun updateCatalogueStartup() {
        val app = getApplication<Application>()
        val eligible = (_servers.value + _workingServers.value).any { candidate ->
            WorkingPoolPolicy.eligible(candidate) &&
                TlsRiskStore.eligibleForAutomaticUse(app, candidate.id) &&
                XrayConfigBuilder.build(candidate, null) != null
        }
        val recovery = if (eligible) false else SuccessfulRouteCache.candidates(app) { candidate ->
            WorkingPoolPolicy.eligible(candidate) &&
                TlsRiskStore.eligibleForAutomaticUse(app, candidate.id) &&
                XrayConfigBuilder.build(candidate, null) != null
        }.isNotEmpty()
        _catalogueStartup.value = CatalogueStartupPolicy.resolve(
            eligible, _servers.value.size, recovery, ServerScanner.catalogueStatus.value)
    }

    private var lastCatalogueRetryElapsed = 0L

    /** Explicit user retry, not a recurring aggressive download / Xray scan. */
    fun retryCatalogueDownload() {
        if (_catalogueStartup.value.ready) return
        val elapsed = android.os.SystemClock.elapsedRealtime()
        if (lastCatalogueRetryElapsed != 0L &&
            elapsed - lastCatalogueRetryElapsed in 0 until 15_000L) return
        lastCatalogueRetryElapsed = elapsed
        _catalogueStartup.value = CatalogueStartupPolicy.State(
            CatalogueStartupPolicy.Phase.LOADING, _servers.value.size,
            "Повторно загружаю список серверов…")
        ServerScanner.retryCatalogueLoad(getApplication())
    }
''')
patch(vm,
    '''        refreshWorkingPool()
    }

    private fun savePref(key: String, value: Boolean)''',
    '''        refreshWorkingPool()
        updateCatalogueStartup()
    }

    private fun savePref(key: String, value: Boolean)''')
patch(vm,
    '''                    (_servers.value.isNotEmpty() || _workingServers.value.isNotEmpty())''',
    '''                    _catalogueStartup.value.ready''')
patch(vm,
    '''                    _servers.value.isNotEmpty()) {
                    // Cache arrived after startup; do not wait for strict 720p reserve.''',
    '''                    _catalogueStartup.value.ready) {
                    // Cache arrived after startup; do not wait for strict 720p reserve.''')
patch(vm,
    '''            WorkingServerStore.revision.collect {
                refreshWorkingPool()
                if (autoSelectionPending.value) {''',
    '''            WorkingServerStore.revision.collect {
                refreshWorkingPool()
                updateCatalogueStartup()
                if (autoSelectionPending.value) {''')
patch(vm,
    '''        setConnectionMode(ConnectionMode.AUTO)
        if (SessionTimer.expireIfDue(getApplication()) ||''',
    '''        setConnectionMode(ConnectionMode.AUTO)
        if (!_catalogueStartup.value.ready && VpnController.state.value != VpnState.Connected) {
            updateCatalogueStartup()
            if (!_catalogueStartup.value.ready) {
                _vpnError.value = "Сначала загружается список серверов. Подключение пока недоступно."
                ServerScanner.request()
                return
            }
        }
        if (SessionTimer.expireIfDue(getApplication()) ||''')
patch(vm,
    '''                _servers.value = ServerStore.loadCached(getApplication(), favoriteIds)
                if (_selectedServer.value == null) {''',
    '''                _servers.value = ServerStore.loadCached(getApplication(), favoriteIds)
                updateCatalogueStartup()
                if (_selectedServer.value == null) {''')
patch(vm,
    '''        viewModelScope.launch {
            ServerRepository.latestStatuses.collect { statuses ->''',
    '''        viewModelScope.launch {
            ServerScanner.catalogueStatus.collect { updateCatalogueStartup() }
        }
        viewModelScope.launch {
            ServerRepository.latestStatuses.collect { statuses ->''')
patch(vm,
    '''                    ServerStore.saveCached(ctx, _servers.value)
                    prefs.edit().putInt("catalogue_source_page_v1",''',
    '''                    ServerStore.saveCached(ctx, _servers.value)
                    updateCatalogueStartup()
                    prefs.edit().putInt("catalogue_source_page_v1",''')

scanner = base/'vpn/ServerScanner.kt'
patch(scanner,
    '    private val catalogueWake = Channel<Unit>(Channel.CONFLATED)\n',
    '''    private val catalogueWake = Channel<Unit>(Channel.CONFLATED)
    private var manualCatalogueRetry = false
''')
patch(scanner,
    '''    fun request(force: Boolean = false) {''',
    '''    /** Only user-triggered bootstrap reload; no heavy probing or unbounded retries. */
    fun retryCatalogueLoad(context: Context) {
        manualCatalogueRetry = true
        context.getSharedPreferences(ServerStore.SETTINGS_PREFS, Context.MODE_PRIVATE)
            .edit().putLong(ServerStore.CATALOGUE_ATTEMPT_KEY, 0L).apply()
        _catalogueStatus.value = "Повторная загрузка списка серверов…"
        catalogueWake.trySend(Unit)
    }

    fun request(force: Boolean = false) {''')
patch(scanner,
    '''                    if (CatalogueRefreshPolicy.isDue(now, cached.size, lastSuccess,
                            lastFailureAtMs, failureCount, verified,
                            adequateBackups = enoughForPower)) {
''',
    '''                    if (manualCatalogueRetry || CatalogueRefreshPolicy.isDue(
                            now, cached.size, lastSuccess, lastFailureAtMs, failureCount,
                            verified, adequateBackups = enoughForPower)) {
                        manualCatalogueRetry = false
''')

ui = base/'ui/screens/home/HomeScreen.kt'
patch(ui,
    '''    val error by vm.vpnError.collectAsStateWithLifecycle()
''',
    '''    val error by vm.vpnError.collectAsStateWithLifecycle()
    val catalogueStartup by vm.catalogueStartup.collectAsStateWithLifecycle()
''')
patch(ui,
    '''    Box(
        modifier = Modifier.fillMaxSize().background(
            Brush.verticalGradient(''',
    '''    // First installation has no usable server until the source download has
    // delivered real, compatible configs. Keep STOP/Kill Switch UI accessible.
    if (!catalogueStartup.ready && !connected && !connectionUi.busy && !connectionUi.blocked) {
        CatalogueStartupScreen(
            status = catalogueStartup,
            onRetry = vm::retryCatalogueDownload,
            onSettings = onSettings
        )
        return
    }
    Box(
        modifier = Modifier.fillMaxSize().background(
            Brush.verticalGradient(''')
print('Installed explicit server catalogue loading stage, no fabricated progress, safe offline cache fallback.')
