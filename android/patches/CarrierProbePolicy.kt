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

    /** Selected cellular network does not by itself imply mobile Internet works. */
    fun mobileNetworkSummary(validated: Boolean, internetCapability: Boolean): String =
        "Android: мобильная сеть обнаружена; INTERNET=" +
            (if (internetCapability) "да" else "нет") +
            ", VALIDATED=" + (if (validated) "да" else "нет") +
            ". Отсутствие VALIDATED не доказывает блокировку сайтов оператором."

    fun unusableDefault(transport: String): String =
        "Тест через SIM не запускался: сеть приложения по умолчанию — " +
            transport + ". Для сравнения нужна именно мобильная сеть " +
            "по умолчанию без активного VPN. Защита и настройки не изменены."

    fun routeComparison(cellularControl: Boolean, defaultControl: Boolean): String =
        when {
            defaultControl && !cellularControl ->
                "Контрольный HTTPS по системному маршруту отвечает, а при явной " +
                    "привязке к мобильной сети нет: возможна ошибка выбора сети " +
                    "или ограничения Android. Это не доказательство блока МегаФоном."
            !defaultControl && !cellularControl ->
                "Контрольный HTTPS не ответил ни по системному, ни по выбранному " +
                    "мобильному маршруту. Причина может быть в Android, DNS, сети " +
                    "или операторе; блокировка МегаФоном не подтверждена."
            else ->
                "Сравнение маршрутов выполнено. Доступность HTTPS не доказывает, " +
                    "что VPN классифицируется оператором как VK."
        }

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
