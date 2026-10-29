package com.secureconnect.app.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class PublicCandidateSourcePolicyTest {
    @Test fun explicitlyTrustedCloudSourceIsAccepted() {
        val known = mapOf("au1rxx" to "Au1rxx/free-vpn-subscriptions")
        assertEquals("Au1rxx/free-vpn-subscriptions",
            PublicCandidateSourcePolicy.nameFor("au1rxx", known))
        assertEquals("TelegaVPN/free-vpn-keys",
            PublicCandidateSourcePolicy.nameFor("telega_ru", known))
    }
    @Test fun unknownOrEmptyCloudSourceRemainsRejected() {
        assertNull(PublicCandidateSourcePolicy.nameFor("unknown-site", emptyMap()))
        assertNull(PublicCandidateSourcePolicy.nameFor("", emptyMap()))
        assertNull(PublicCandidateSourcePolicy.nameFor("../telega_ru", emptyMap()))
    }
}
