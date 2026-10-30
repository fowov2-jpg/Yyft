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

    @Test fun gatewayResponseNeverClaimsVpnConfirmation() {
        assertTrue(ManualPayloadCodec.responseCategory("HTTP/1.1 200 OK")
            .contains("НЕ подтверждены"))
        assertTrue(ManualPayloadCodec.responseCategory("HTTP/1.1 403 Forbidden")
            .contains("не подтверждён"))
        assertTrue(ManualPayloadCodec.responseCategory(null)
            .contains("не подтверждён"))
    }
}
