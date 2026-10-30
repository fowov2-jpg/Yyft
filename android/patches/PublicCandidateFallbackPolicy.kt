package com.secureconnect.app.vpn

/** Distinguish an empty verified publication from incompatible imported links. */
internal object PublicCandidateFallbackPolicy {
    fun tryAlternateEndpoint(publishedCount: Int, acceptedCount: Int): Boolean =
        publishedCount in 1..24 && acceptedCount == 0
}
