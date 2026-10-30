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

    /** First argument ALWAYS represents the primary, ordinary Android route. */
    fun routeComparison(defaultControl: Boolean, pinnedControl: Boolean): String =
        when {
            defaultControl && !pinnedControl ->
                "Основной системный HTTPS отвечает; отдельный Network.openConnection " +
                    "не ответил. Значит прежний метод диагностики давал ложные " +
                    "отрицательные результаты. Это не блокировка сайтов оператором."
            !defaultControl && pinnedControl ->
                "Основной системный HTTPS не ответил, но дополнительная привязка " +
                    "к мобильной сети отвечает. Есть различие маршрутизации Android; " +
                    "блокировка оператором не доказана."
            !defaultControl && !pinnedControl ->
                "Оба метода не получили HTTPS-ответ: причина может быть в Android, " +
                    "DNS, политике VPN или мобильной сети. Блокировка МегаФоном " +
                    "не подтверждена."
            else ->
                "Оба метода получили HTTPS-ответ. Это не доказывает, что " +
                    "VPN-трафик классифицируется оператором как VK."
        }

    fun routeChangedNotice(): String =
        "Проверка остановлена: во время теста изменился основной маршрут " +
            "Android или переподключился VPN. Результаты недостоверны; " +
            "выводов о блокировках оператора делать нельзя."

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
                "Ни для VK, ни для контрольного HTTPS не получен ответ. " +
                    "Причина не определена: ошибка DNS, Android, сети или сайта. " +
                    "Это не доказательство блокировки оператором."
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
