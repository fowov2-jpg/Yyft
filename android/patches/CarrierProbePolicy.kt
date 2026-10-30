package com.secureconnect.app.ui.screens.settings

/** Public website accessibility is not evidence of VPN whitelist eligibility. */
internal object CarrierProbePolicy {
    /** Connected VPN can forbid physical-network bypass; do not test
     *  operator site allowlists by treating VPN lockdown as a website failure.
     *  This app never turns off VPN or weakens a kill switch automatically.
     */
    fun vpnActiveNotice(): String =
        "Проверка через SIM-карту не запускалась: VPN сейчас подключён. " +
            "Android может запрещать прямые соединения мимо VPN, особенно в режиме " +
            "«Блокировать подключения без VPN». Ранее показанные ошибки всех четырёх " +
            "сайтов не подтверждают блокировку МегаФоном. Для проверки оператора " +
            "нужен отдельный добровольный тест без VPN; тогда сайты увидят мобильный IP. " +
            "VPN и Kill Switch не изменены. Нельзя утверждать, что МегаФон " +
            "относит VPN-трафик к белому списку VK или увеличивает скорость."

    fun progress(index: Int, total: Int, label: String, completed: List<String>): String =
        "Проверка " + index + "/" + total + ": " + label + "\n" +
            completed.joinToString("\n")


    fun conclusion(cellular: Boolean, vk: Boolean, ordinaryHttps: Boolean,
                   vpnConnected: Boolean): String {
        if (!cellular) return "Мобильная сеть не найдена. Включите мобильные данные. Результат не определён."
        if (vpnConnected && !vk && !ordinaryHttps) return vpnActiveNotice()
        val availability = when {
            vk && !ordinaryHttps ->
                "VK отвечает, а контрольный HTTPS не ответил. Возможна избирательная доступность сайтов."
            vk && ordinaryHttps ->
                "VK и контрольный HTTPS отвечают. Различий доступности этим тестом не обнаружено."
            !vk && ordinaryHttps ->
                "Контрольный HTTPS отвечает, а VK не ответил. Причина не определена."
            else ->
                "Оба сайта не ответили. Причина не определена."
        }
        val vpn = if (vpnConnected)
            "Xray сообщает о подключении VPN."
        else
            "Xray не сообщает о подключённом VPN."
        return availability + " " + vpn +
            " Нельзя утверждать, что МегаФон относит VPN-трафик к белому списку VK " +
            "или увеличивает скорость: нужны замеры на SIM-карте при ограничениях."
    }
}
