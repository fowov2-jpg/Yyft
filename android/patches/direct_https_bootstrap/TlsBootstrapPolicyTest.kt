package com.secureconnect.app.vpn

import java.security.cert.CertificateException
import java.security.cert.CertPathValidatorException
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.SSLProtocolException
import javax.net.ssl.SSLPeerUnverifiedException
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TlsBootstrapPolicyTest {
    @Test fun autoUsesLiveCertificateVerifiedHttpsWithoutSecondXray() {
        assertFalse(TlsBootstrapPolicy.needsStandalonePreflight(true, false, false))
        assertFalse(TlsBootstrapPolicy.needsStandalonePreflight(true, true, false))
        assertTrue(TlsBootstrapPolicy.needsStandalonePreflight(false, false, false))
        assertFalse(TlsBootstrapPolicy.needsStandalonePreflight(false, true, false))
        assertFalse(TlsBootstrapPolicy.needsStandalonePreflight(false, false, true))
    }

    @Test fun certificateFailureIsRiskButTimeoutOrGenericProtocolErrorIsNot() {
        assertTrue(TlsBootstrapPolicy.isCertificateFailure(
            SSLHandshakeException("chain validation failed").apply {
                initCause(CertificateException("unknown CA"))
            }))
        assertTrue(TlsBootstrapPolicy.isCertificateFailure(
            Exception(CertPathValidatorException("revoked"))))
        assertTrue(TlsBootstrapPolicy.isCertificateFailure(
            SSLPeerUnverifiedException("hostname mismatch")))
        assertFalse(TlsBootstrapPolicy.isCertificateFailure(
            SSLProtocolException("EOF / unrecognized handshake")))
        assertFalse(TlsBootstrapPolicy.isCertificateFailure(
            java.net.SocketTimeoutException("timeout")))
    }

    @Test fun oneUntrustedTlsPeerOverridesAnotherHealthyControlSite() {
        assertTrue(TlsBootstrapPolicy.hasCertificateProblem(
            listOf("ok", "tls_certificate")))
        assertFalse(TlsBootstrapPolicy.hasCertificateProblem(
            listOf("tls", "ok")))
        assertFalse(TlsBootstrapPolicy.hasCertificateProblem(emptyList()))
    }
}
