package com.secureconnect.app.vpn

/** Pure, deterministic combinations. Tests ONE user-authorized gateway, never
 * scans a list of hosts, ports or other people's proxy services.
 */
internal object AutoPayloadGenerator {
    const val MAX_ATTEMPTS = 24
    const val TARGET_HOST = "example.com"
    const val TARGET_PORT = 443
    const val GAP_MS = 750L

    data class Candidate(
        val label: String,
        val template: String,
        val encoded: ManualPayloadCodec.Encoding
    )

    fun isValidHost(value: String): Boolean =
        value.length in 4..253 && value.contains('.') &&
            !value.contains("..") &&
            Regex("^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])$").matches(value)

    /** user front name is a header value, not a way to rewrite TCP/TLS destination. */
    fun generate(front: String): List<Candidate> {
        if (!isValidHost(front)) return emptyList()
        val authority = "$TARGET_HOST:$TARGET_PORT"
        val requestTargets = listOf(authority, "https://$authority", "Https://$front")
        val headerValues = listOf(authority, front, "Https://$front")
        val extra = listOf(
            "",
            "X-Online-Host: $front[crlf]",
            "Referer: Https://$front[crlf]" +
                "X-Online-Host: Https://$front[crlf]" +
                "X-Forwarded-For: Https://$front[crlf]"
        )
        val candidates = mutableListOf<Candidate>()
        for (requestTarget in requestTargets) {
            for (header in headerValues) {
                for (added in extra) {
                    val t = "CONNECT $requestTarget HTTP/1.1[crlf]" +
                        "Host: $header[crlf]" +
                        "Connection: keep-alive[crlf]" +
                        "User-Agent: Dalvik/2.1.0 (Linux; Android 16)[crlf]" +
                        added + "[crlf]"
                    val encoded = ManualPayloadCodec.encode(t)
                    if (encoded.valid) {
                        candidates.add(Candidate(
                            "CONNECT=$requestTarget · Host=$header · extras=${if (added.isEmpty()) "none" else "added"}",
                            t, encoded
                        ))
                    }
                }
            }
        }
        // No randomness or uncontrolled permutation; reproducible test evidence.
        return candidates.distinctBy { it.template }.take(MAX_ATTEMPTS)
    }

    /** A 200 from a web site is never proof of HTTP CONNECT tunneling. */
    fun isConnectEstablished(statusLine: String?): Boolean =
        statusLine != null &&
            Regex("^HTTP/1\\.[01] 200(?:[ \\t]|$)").containsMatchIn(statusLine)

    fun isHttpPayloadDelivered(statusLine: String?): Boolean =
        statusLine != null &&
            Regex("^HTTP/1\\.[01] (?:2\\d\\d|3\\d\\d)(?:[ \\t]|$)")
                .containsMatchIn(statusLine)
}
