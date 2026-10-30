package com.secureconnect.app.vpn

import java.nio.charset.StandardCharsets

/**
 * One bounded, explicit HTTP request. Does not interpret or "correct" HTTP-BUG:
 * exact user syntax is preserved, apart from converting [crlf] to CRLF.
 */
internal object ManualPayloadCodec {
    const val MAX_BYTES = 4096
    const val MAX_HEADERS = 20

    const val USER_TEMPLATE =
        "CONNECT Https://vk.com HTTP/1.1[crlf]" +
        "Host: Https://vk.com[crlf]" +
        "Connection: keep-alive[crlf]" +
        "User-Agent: Dalvik/2.1.0 (Linux; U; Android 16; 2607APCA5G Build/BP2A.250605.031.A3)[crlf]" +
        "Referer: Https://vk.com[crlf]" +
        "X-Online-Host: Https://vk.com[crlf]" +
        "X-Forwarded-For: Https://vk.com[crlf][crlf]"

    const val STANDARD_TEMPLATE =
        "CONNECT vk.com:443 HTTP/1.1[crlf]" +
        "Host: vk.com:443[crlf]" +
        "Connection: keep-alive[crlf][crlf]"

    data class Encoding(val bytes: ByteArray, val preview: String, val error: String?) {
        val valid: Boolean get() = error == null
    }

    fun encode(template: String): Encoding {
        fun reject(reason: String) = Encoding(byteArrayOf(), "", reason)
        if (template.isBlank()) return reject("Введите HTTP-запрос.")
        if (template.length > MAX_BYTES) return reject("Слишком длинный шаблон.")
        val normalized = template.replace("\r\n", "\n").replace('\r', '\n')
            .replace("[crlf]", "\n", ignoreCase = true)
        if (!normalized.endsWith("\n\n")) return reject("Завершите запрос двумя [crlf].")
        if (normalized.any { it == '\u0000' || (it.code < 32 && it != '\n' && it != '\t') })
            return reject("Недопустимый управляющий символ.")
        val lines = normalized.split('\n')
        if (lines.size < 4 || lines[0].isBlank()) return reject("Нет строки HTTP-запроса.")
        if (!Regex("^[A-Z]{2,12} [^\\n]{1,512} HTTP/1\\.[01]$").matches(lines[0]))
            return reject("Ожидается METHOD target HTTP/1.0 или HTTP/1.1.")
        val firstBlank = lines.indexOfFirst { it.isEmpty() }
        if (firstBlank < 1 || lines.drop(firstBlank).any { it.isNotEmpty() })
            return reject("Допускается только один запрос без тела.")
        if (firstBlank - 1 > MAX_HEADERS) return reject("Не более 20 заголовков.")
        for (line in lines.subList(1, firstBlank)) {
            val split = line.indexOf(':')
            if (split <= 0 || !Regex("^[A-Za-z0-9-]{1,64}$").matches(line.substring(0, split)))
                return reject("Неверное имя HTTP-заголовка.")
            if (line.length > 512) return reject("Заголовок длиннее 512 символов.")
        }
        val wire = normalized.replace("\n", "\r\n")
        val bytes = wire.toByteArray(StandardCharsets.UTF_8)
        if (bytes.size > MAX_BYTES) return reject("Максимум 4096 байт.")
        return Encoding(bytes, wire.replace("\r\n", "⏎\n"), null)
    }

    fun responseCategory(line: String?): String = when {
        line == null -> "HTTP-ответ не получен. VPN не подтверждён."
        Regex("^HTTP/1\\.[01] 2\\d\\d( |$)").containsMatchIn(line) ->
            "HTTP 2xx: шлюз ответил. VPN и обход ограничений НЕ подтверждены."
        line.startsWith("HTTP/1.") ->
            "Ответ шлюза: " + line.take(110) + ". VPN не подтверждён."
        else -> "Нестандартный ответ шлюза. VPN не подтверждён."
    }
}
