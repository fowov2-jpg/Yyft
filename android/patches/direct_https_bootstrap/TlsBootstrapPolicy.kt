package com.secureconnect.app.vpn

import java.security.cert.CertificateException
import java.security.cert.CertPathValidatorException
import javax.net.ssl.SSLPeerUnverifiedException

/**
 * Automatic startup uses the same certificate-verified HTTPS probe as the
 * Connected gate. It must not spin up a second native Xray controller first.
 * Explicit manual mode may still run the standalone ChatGPT trust preflight.
 */
internal object TlsBootstrapPolicy {
    fun needsStandalonePreflight(
        automaticMode: Boolean,
        recentlyProvenIdenticalConfig: Boolean,
        riskApprovedForSession: Boolean
    ): Boolean = !automaticMode && !recentlyProvenIdenticalConfig &&
        !riskApprovedForSession

    /** Generic TLS handshake failures are NOT evidence of certificate MITM. */
    fun isCertificateFailure(error: Throwable): Boolean {
        var cause: Throwable? = error
        var hops = 0
        while (cause != null && hops++ < 12) {
            if (cause is CertificateException ||
                cause is CertPathValidatorException ||
                cause is SSLPeerUnverifiedException) return true
            if (cause.cause === cause) break
            cause = cause.cause
        }
        return false
    }

    /** A single untrusted peer is a hard fail even if another CDN responds. */
    fun hasCertificateProblem(stages: List<String>): Boolean =
        stages.any { it == "tls_certificate" }
}
