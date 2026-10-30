package com.secureconnect.app.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AutoPayloadGeneratorTest {
    @Test fun generatesBoundedUniqueAndValidRequests() {
        val candidates = AutoPayloadGenerator.generate("vk.com")
        assertEquals(AutoPayloadGenerator.MAX_ATTEMPTS, candidates.size)
        assertEquals(candidates.size, candidates.map { it.template }.toSet().size)
        assertTrue(candidates.all { it.encoded.valid })
        assertTrue(candidates.all {
            it.encoded.bytes.size in 1..ManualPayloadCodec.MAX_BYTES
        })
        assertTrue(candidates.first().template.startsWith(
            "CONNECT example.com:443 HTTP/1.1[crlf]Host: example.com:443"))
    }

    @Test fun rejectsInvalidHeaderHostAndCannotInjectNewLines() {
        assertTrue(AutoPayloadGenerator.generate("vk.com\nHost: attacker.example").isEmpty())
        assertTrue(AutoPayloadGenerator.generate("vk.com[crlf]").isEmpty())
        assertTrue(AutoPayloadGenerator.generate("").isEmpty())
        assertFalse(AutoPayloadGenerator.isValidHost("https://vk.com"))
    }

    @Test fun only200ConnectStatusCountsAsEstablished() {
        assertTrue(AutoPayloadGenerator.isConnectEstablished("HTTP/1.1 200 Connection established"))
        assertTrue(AutoPayloadGenerator.isConnectEstablished("HTTP/1.0 200"))
        assertFalse(AutoPayloadGenerator.isConnectEstablished("HTTP/1.1 400 Bad Request"))
        assertFalse(AutoPayloadGenerator.isConnectEstablished("HTTP/1.1 201 Created"))
        assertFalse(AutoPayloadGenerator.isConnectEstablished(null))
        assertFalse(AutoPayloadGenerator.isConnectEstablished("HTTP/1.1 2000 bogus"))
    }

    @Test fun tunneledHttpNeedsReal2xxOr3xxResponse() {
        assertTrue(AutoPayloadGenerator.isHttpPayloadDelivered("HTTP/1.1 200 OK"))
        assertTrue(AutoPayloadGenerator.isHttpPayloadDelivered("HTTP/1.1 301 Moved"))
        assertFalse(AutoPayloadGenerator.isHttpPayloadDelivered("HTTP/1.1 400 Bad Request"))
        assertFalse(AutoPayloadGenerator.isHttpPayloadDelivered("HTTP/1.1 407 Proxy Auth Required"))
        assertFalse(AutoPayloadGenerator.isHttpPayloadDelivered(null))
        assertFalse(AutoPayloadGenerator.isHttpPayloadDelivered("HTTP/1.1 2000 OK"))
    }
}
