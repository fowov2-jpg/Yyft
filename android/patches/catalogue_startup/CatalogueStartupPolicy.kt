package com.secureconnect.app.viewmodel

/** UI gate for the first AUTO connection, not a reachability/quality certificate. */
internal object CatalogueStartupPolicy {
    enum class Phase { LOADING, READY_CACHE, READY_RECOVERY, ERROR }

    data class State(
        val phase: Phase,
        val storedCount: Int,
        val detail: String
    ) {
        val ready: Boolean get() = phase == Phase.READY_CACHE || phase == Phase.READY_RECOVERY
    }

    fun resolve(
        hasCompatibleCatalogNode: Boolean,
        storedCount: Int,
        hasVerifiedRecovery: Boolean,
        scannerMessage: String
    ): State {
        val count = storedCount.coerceIn(0, 240)
        if (hasCompatibleCatalogNode) return State(Phase.READY_CACHE, count,
            "Список серверов готов: $count сохранено. VPN-проверка начнётся после нажатия.")
        if (hasVerifiedRecovery) return State(Phase.READY_RECOVERY, count,
            "Доступен ранее успешно проверенный сервер из защищённого кэша. Перед подключением проверю его заново.")
        val message = scannerMessage.trim().take(180)
        val lowered = message.lowercase()
        val failed = listOf("нет сети", "не удалось", "временно недоступны",
            "все источники отключены", "загрузка остановлена").any { lowered.contains(it) }
        return if (failed) State(Phase.ERROR, count,
            "Список серверов пока не получен. ${message.ifBlank { "Проверь интернет и повтори загрузку." }}")
        else State(Phase.LOADING, count,
            if (message.isBlank() || message.contains("ожидаю", ignoreCase = true))
                "Загружается список серверов из подписок…"
            else message)
    }
}