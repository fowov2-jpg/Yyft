package com.secureconnect.app.vpn

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ManualPayloadCodecTest {
    @Test fun preservesUserTemplateApartFromCrLfExpansion() {
        val packet = ManualPayloadCodec.encode(ManualPayloadCodec.USER_TEMPLATE)
        assertTrue(packet.error.orEmpty(), packet.valid)
        val wire = String(packet.bytes, Charsets.UTF_8)
        assertTrue(wire.startsWith("CONNECT Https://vk.com HTTP/1.1\r\n"))
        assertTrue(wire.contains("X-Forwarded-For: Https://vk.com\r\n"))
        assertTrue(wire.endsWith("\r\n\r\n"))
        assertFalse(wire.contains("[crlf]"))
    }

    @Test fun acceptsOrdinaryConnectAndNewlineVariants() {
        assertTrue(ManualPayloadCodec.encode(ManualPayloadCodec.STANDARD_TEMPLATE).valid)
        assertTrue(ManualPayloadCodec.encode(
            "CONNECT vk.com:443 HTTP/1.1\nHost: vk.com:443\n\n").valid)
        assertTrue(ManualPayloadCodec.encode(
            "CONNECT vk.com:443 HTTP/1.1\r\nHost: vk.com:443\r\n\r\n").valid)
    }

    @Test fun rejectsUnterminatedAndInvalidHeaders() {
        assertFalse(ManualPayloadCodec.encode("GET / HTTP/1.1[crlf]Host: a[crlf]").valid)
        assertFalse(ManualPayloadCodec.encode(
            "GET / HTTP/1.1[crlf]Bad Header: a[crlf][crlf]").valid)
        assertFalse(ManualPayloadCodec.encode(
            "GET / HTTP/1.1[crlf]Host: a\u0000[crlf][crlf]").valid)
    }

    @Test fun rejectsPipelinedMultipleRequestsAndOversize() {
        assertFalse(ManualPayloadCodec.encode(
            "GET / HTTP/1.1[crlf]Host: a[crlf][crlf]GET / HTTP/1.1[crlf][crlf]").valid)
        assertFalse(ManualPayloadCodec.encode(
            "GET / HTTP/1.1[crlf]Host: " + "a".repeat(5000) + "[crlf][crlf]").valid)
    }

    @Test fun vkPlainGetIsAValidStandaloneWebCheck() {
        val wire = ManualPayloadCodec.encode(ManualPayloadCodec.WEBSITE_TEMPLATE)
        assertTrue(wire.error.orEmpty(), wire.valid)
        assertTrue(String(wire.bytes, Charsets.UTF_8).startsWith("GET / HTTP/1.1\r\n"))
        assertTrue(String(wire.bytes, Charsets.UTF_8).contains("Host: vk.com\r\n"))
    }

    @Test fun warningsAreAdvisoryAndNoAutomaticRetry() {
        assertTrue(ManualPayloadCodec.configurationWarning("vk.com", "80", true)!!
            .contains("SSLException"))
        assertTrue(ManualPayloadCodec.configurationWarning("vk.com", "443", true)!!
            .contains("не наш HTTP CONNECT-прокси"))
        assertTrue(ManualPayloadCodec.configurationWarning("test.example", "443", false)!!
            .contains("RAW"))
        assertTrue(ManualPayloadCodec.configurationWarning("test.example", "443", true) == null)
    }

    @Test fun separatesTlsFailureFromSuccessfulTlsButBadHttp() {
        assertTrue(ManualPayloadCodec.failureSummary("SIM", "TLS", "SSLException", true, 80)
            .contains("TLS-рукопожатие на порту 80"))
        assertTrue(ManualPayloadCodec.failureSummary("SIM", "DNS", "UnknownHostException", true, 443)
            .contains("DNS"))
        assertTrue(ManualPayloadCodec.failureSummary("SIM", "TCP", "SocketTimeoutException", true, 443)
            .contains("TCP"))
        assertTrue(ManualPayloadCodec.responseCategory("HTTP/1.1 400 Bad Request")
            .contains("HTTP 400"))
        assertFalse(ManualPayloadCodec.responseCategory("HTTP/1.1 400 Bad Request")
            .contains("успешный VPN"))
    }

    @Test fun gatewayResponseNeverClaimsVpnConfirmation() {
        assertTrue(ManualPayloadCodec.responseCategory("HTTP/1.1 200 OK")
            .contains("НЕ подтверждены"))
        assertTrue(ManualPayloadCodec.responseCategory("HTTP/1.1 403 Forbidden")
            .contains("не подтверждён"))
        assertTrue(ManualPayloadCodec.responseCategory(null)
            .contains("не подтверждён"))
    }
}
