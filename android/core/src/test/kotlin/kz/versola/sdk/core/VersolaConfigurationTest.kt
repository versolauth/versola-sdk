package kz.versola.sdk.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class VersolaConfigurationTest {

    private fun configure(
        issuer: String = "https://id.versola.kz",
        clientId: String = "mobile-app",
        redirectUri: String = "https://app.example.com/oauth",
    ) = VersolaConfiguration.create(issuer, clientId, redirectUri)

    @Test
    fun `an https redirect is treated as a verified App Link`() {
        assertEquals(RedirectUriKind.AppLink, configure().redirectUri.kind)
    }

    @Test
    fun `a private-use scheme is accepted and warned about`() {
        // #5: custom schemes are accepted, because plenty of apps have one registered
        // already, but any app on the device can claim the same one.
        val configuration = configure(redirectUri = "com.example.app:/oauth")

        assertEquals(RedirectUriKind.CustomScheme, configuration.redirectUri.kind)
        assertNotNull(configuration.redirectUriWarning)
        assertTrue(configuration.redirectUriWarning!!.contains("assetlinks.json"))
    }

    @Test
    fun `an App Link produces no warning`() {
        assertNull(configure().redirectUriWarning)
    }

    @Test
    fun `loopback is recognised and not warned about`() {
        assertEquals(RedirectUriKind.Loopback, configure(redirectUri = "http://127.0.0.1:8080/oauth").redirectUri.kind)
        assertNull(configure(redirectUri = "http://localhost/oauth").redirectUriWarning)
    }

    @Test
    fun `cleartext http to a remote host is refused`() {
        assertThrows(VersolaError.Configuration::class.java) {
            configure(redirectUri = "http://app.example.com/oauth")
        }
    }

    @Test
    fun `a redirect carrying a fragment is refused`() {
        // The server refuses it too (AuthorizeRequestParser.parseRedirectUri), so accepting
        // it here would only move the failure somewhere less legible.
        assertThrows(VersolaError.Configuration::class.java) {
            configure(redirectUri = "https://app.example.com/oauth#done")
        }
    }

    @Test
    fun `a relative redirect is refused`() {
        assertThrows(VersolaError.Configuration::class.java) { configure(redirectUri = "/oauth") }
    }

    @Test
    fun `an opaque https redirect with no host is refused rather than treated as an App Link`() {
        // "https:callback" has a scheme and is absolute, but no host: Android cannot route it
        // as an HTTPS App Link redirect, so it must not silently pass as one.
        assertThrows(VersolaError.Configuration::class.java) { configure(redirectUri = "https:callback") }
    }

    @Test
    fun `a non-https issuer is refused`() {
        assertThrows(VersolaError.Configuration::class.java) { configure(issuer = "http://id.versola.kz") }
    }

    @Test
    fun `an opaque issuer with no host is refused rather than passing the scheme check`() {
        // "https:issuer" passes a scheme-only check, then has no host to append the
        // well-known path to — which must fail here, not later inside discovery.
        assertThrows(VersolaError.Configuration::class.java) { configure(issuer = "https:issuer") }
    }

    @Test
    fun `an issuer carrying a query or fragment is refused`() {
        // RFC 8414 §2: the well-known path is appended verbatim, so neither can be present.
        assertThrows(VersolaError.Configuration::class.java) { configure(issuer = "https://id.versola.kz?x=1") }
        assertThrows(VersolaError.Configuration::class.java) { configure(issuer = "https://id.versola.kz#x") }
    }

    @Test
    fun `a blank client id is refused`() {
        assertThrows(VersolaError.Configuration::class.java) { configure(clientId = "  ") }
    }

    @Test
    fun `a trailing slash on the issuer is normalised away`() {
        // Otherwise the well-known URL doubles the slash and the iss comparison fails against
        // a server that returns the canonical form.
        assertEquals("https://id.versola.kz", configure(issuer = "https://id.versola.kz/").issuer)
    }

    @Test
    fun `no public API anywhere in core can carry a client secret`() {
        // Asserted against the published surface rather than against this class alone: a
        // mobile client is public (#1 §2), and "we did not add a secret parameter" is not the
        // property that matters — "an integrator cannot find one to fill in" is. The dump is
        // what `apiCheck` gates, so a secret can only reach the API by passing through here.
        val dump = java.io.File("api/core.api")
        assertTrue("api/core.api should be readable from the module directory", dump.isFile)

        val offending = dump.readLines().filter { line ->
            line.contains("secret", ignoreCase = true) || line.contains("clientAssertion", ignoreCase = true)
        }

        assertEquals("no public member may name a client secret: $offending", emptyList<String>(), offending)
    }

    @Test
    fun `an issuer with a path keeps it`() {
        // Multi-tenant deployments put the tenant in the path; discovery appends to it.
        val configuration = configure(issuer = "https://id.example.com/tenants/acme")

        assertEquals("https://id.example.com/tenants/acme", configuration.issuer)
        assertEquals(
            "https://id.example.com/tenants/acme/.well-known/openid-configuration",
            wellKnownUrl(configuration.issuer),
        )
    }

    @Test
    fun `the post-logout redirect is optional and held to the login redirect's rules`() {
        assertNull(configure().postLogoutRedirectUri)

        val withRedirect = VersolaConfiguration.create(
            "https://id.example.com", "mobile-app", "https://app.example.com/oauth",
            postLogoutRedirectUri = "https://app.example.com/signed-out",
        )
        assertEquals("https://app.example.com/signed-out", withRedirect.postLogoutRedirectUri?.value)
        assertEquals(RedirectUriKind.AppLink, withRedirect.postLogoutRedirectUri?.kind)

        assertThrows(VersolaError.Configuration::class.java) {
            VersolaConfiguration.create(
                "https://id.example.com", "mobile-app", "https://app.example.com/oauth",
                postLogoutRedirectUri = "http://app.example.com/signed-out",
            )
        }
    }
}
