package com.secureconnect.app.vpn

/** Pure startup policy: reuse existing Xray auto-select instead of trying to
 * invent an HTTP CONNECT gateway. No new loops or network traffic here.
 */
internal object AutomaticRoutePolicy {
    enum class Action { KEEP_SESSION, WAIT, START_XRAY, STOP_REQUIRED }

    fun decide(state: VpnState, pending: Boolean, connecting: Boolean): Action = when {
        state == VpnState.Connected -> Action.KEEP_SESSION
        state == VpnState.Blocked || state == VpnState.Stopping -> Action.STOP_REQUIRED
        state == VpnState.Connecting || state == VpnState.Validating || pending || connecting ->
            Action.WAIT
        else -> Action.START_XRAY
    }

    fun message(action: Action, hasServer: Boolean): String = when(action) {
        Action.KEEP_SESSION -> if (hasServer)
            "Основной Xray подключён. Не переключаю рабочую сессию ради поиска шлюза."
        else "Туннель активен. Сервер уточняется; соединение не прерываю."
        Action.WAIT -> "Xray уже подключается или проверяет сервер — повторный запуск не нужен."
        Action.STOP_REQUIRED ->
            "VPN завершает работу либо Kill Switch блокирует сеть. Управляй защитой на главном экране."
        Action.START_XRAY ->
            "Без ручного HTTP-шлюза используется существующий Xray-каталог и безопасный автовыбор."
    }
}
