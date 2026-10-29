package com.secureconnect.app.vpn

/**
 * Only named, deliberately allowlisted cloud checkers may add shared public
 * VPN URIs. Local Xray/TLS verification is still mandatory.
 */
internal object PublicCandidateSourcePolicy {
    fun nameFor(sourceId: String, configured: Map<String, String>): String? {
        if (sourceId.isEmpty()) return null
        return configured[sourceId] ?: when (sourceId) {
            // The cloud checker has this additional fixed public repository.
            "telega_ru" -> "TelegaVPN/free-vpn-keys"
            else -> null
        }
    }
}
