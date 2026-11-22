package versola.sdk.core

import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import versola.oauth.core.DiscoveryService

/** [EdgeMetadata]: what the core asks its metadata, answered from the configuration with no network. */
class EdgeMetadataTest {

    private val edge = "https://edge.example.com"

    private suspend fun fetch(
        issuer: String = "https://id.example.com",
        edgeUrl: String = edge,
        clientId: String = "mobile-app",
    ) = EdgeMetadata(issuer, edgeUrl, clientId).fetch(issuer)

    @Test
    fun `the issuer is the configured string byte for byte`() = runTest {
        assertEquals("https://id.example.com", fetch(issuer = "https://id.example.com").issuer)
    }

    @Test
    fun `a trailing slash on the configured issuer is kept in the issuer and not in the paths`() = runTest {
        val metadata = fetch(issuer = "https://id.example.com/")

        assertEquals("https://id.example.com/", metadata.issuer)
        assertEquals("https://id.example.com/logout", metadata.endSessionEndpoint)
        assertEquals("https://id.example.com/authorize", metadata.authorizationEndpoint)
    }

    @Test
    fun `an issuer with a path keeps it`() = runTest {
        val metadata = fetch(issuer = "https://id.example.com/tenant-a")

        assertEquals("https://id.example.com/tenant-a", metadata.issuer)
        assertEquals("https://id.example.com/tenant-a/logout", metadata.endSessionEndpoint)
    }

    @Test
    fun `the end session endpoint is the issuer's logout`() = runTest {
        assertEquals("https://id.example.com/logout", fetch().endSessionEndpoint)
    }

    @Test
    fun `the token and revocation endpoints are edge's native URLs for the client`() = runTest {
        val metadata = fetch()

        assertEquals("$edge/native/token/mobile-app", metadata.tokenEndpoint)
        assertEquals("$edge/native/revoke/mobile-app", metadata.revocationEndpoint)
    }

    @Test
    fun `a trailing slash on edge's URL does not double the slash`() = runTest {
        assertEquals("$edge/native/token/mobile-app", fetch(edgeUrl = "$edge/").tokenEndpoint)
    }

    @Test
    fun `the client id is path-encoded in both native URLs`() = runTest {
        val metadata = fetch(clientId = "acme/mobile app")

        assertEquals("$edge/native/token/acme%2Fmobile%20app", metadata.tokenEndpoint)
        assertEquals("$edge/native/revoke/acme%2Fmobile%20app", metadata.revocationEndpoint)
    }

    @Test
    fun `dpop is supported with ES256 and iss is always on the redirect`() = runTest {
        val metadata = fetch()

        assertTrue(metadata.supportsDpop)
        assertEquals(listOf("ES256"), metadata.dpopSigningAlgValuesSupported)
        assertTrue(metadata.authorizationResponseIssParameterSupported)
    }

    @Test
    fun `nothing is advertised that the facade has no use for`() = runTest {
        val metadata = fetch()

        assertNull(metadata.jwksUri)
        assertNull(metadata.userinfoEndpoint)
        assertNull(metadata.pushedAuthorizationRequestEndpoint)
    }

    @Test
    fun `a discovery service built on it answers with no network and no cache`() = runTest {
        val metadata = DiscoveryService("https://id.example.com", EdgeMetadata("https://id.example.com", edge, "mobile-app"), EdgeMetadata.NoCache)
            .metadata()

        assertEquals("https://id.example.com", metadata.issuer)
        assertEquals("$edge/native/token/mobile-app", metadata.tokenEndpoint)
    }

    @Test
    fun `the no-op cache holds nothing`() = runTest {
        val cache = EdgeMetadata.NoCache
        cache.save(fetch())

        assertNull(cache.load())
        cache.clear()
        assertSame(EdgeMetadata.NoCache, cache)
    }
}
