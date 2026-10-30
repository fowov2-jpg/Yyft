package com.secureconnect.app.vpn

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PublicCandidateFallbackPolicyTest {
    @Test fun incompatibleNonemptyPagesMustAttemptRawBackup() {
        assertTrue(PublicCandidateFallbackPolicy.tryAlternateEndpoint(24, 0))
        assertTrue(PublicCandidateFallbackPolicy.tryAlternateEndpoint(1, 0))
    }

    @Test fun compatiblePagesDoNotNeedBackup() {
        assertFalse(PublicCandidateFallbackPolicy.tryAlternateEndpoint(24, 1))
        assertFalse(PublicCandidateFallbackPolicy.tryAlternateEndpoint(1, 1))
    }

    @Test fun LegitimatelyEmptyPublicationDoesNotInventServers() {
        assertFalse(PublicCandidateFallbackPolicy.tryAlternateEndpoint(0, 0))
    }

    @Test fun malformedCountsNeverTriggerBackupAsValidatedPublication() {
        assertFalse(PublicCandidateFallbackPolicy.tryAlternateEndpoint(-1, 0))
        assertFalse(PublicCandidateFallbackPolicy.tryAlternateEndpoint(25, 0))
    }
}
