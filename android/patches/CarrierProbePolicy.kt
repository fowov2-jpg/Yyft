package com.secureconnect.app.ui.screens.settings

/** Public website accessibility is not evidence of VPN whitelist eligibility. */
internal object CarrierProbePolicy {
    fun progress(index: Int, total: Int, label: String, completed: List<String>): String =
        "Проверка " + index + "/" + total + ": " + label + "\n" +
            completed.joinToString("\n")


    fun conclusion(cellular: Boolean, vk: Boolean, ordinaryHttps: Boolean,
                   vpnConnected: Boolean): String {
        if (!cellular) return "Мобильная сеть не найдена. Включите мобильные данные. Результат не определён."
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
