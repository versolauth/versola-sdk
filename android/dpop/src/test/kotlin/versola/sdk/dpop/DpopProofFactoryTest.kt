package versola.sdk.dpop

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jwt.SignedJWT
import java.security.MessageDigest
import java.util.Base64
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

private const val TOKEN_ENDPOINT = "https://id.versola.io/token"
private const val EDGE_RESOURCE = "https://versola.io/resources/42/items"

class DpopProofFactoryTest {

    private val key = SoftwareDpopKey()

    private fun factory(
        nonces: DpopNonceCache = DpopNonceCache(),
        clockSkew: ClockSkew = ClockSkew(),
    ) = DpopProofFactory(key, nonces, clockSkew)

    /** Parses with the library auth and edge verify with, so a pass here is a pass there. */
    private fun parse(proof: String): SignedJWT = SignedJWT.parse(proof)

    @Test
    fun `a proof verifies against the key embedded in its own header`() {
        // This is the whole of RFC 9449's trust model: the server has never seen the key
        // before and checks the proof against the one the proof itself carries.
        runTest {
            val jwt = parse(factory().proof("POST", TOKEN_ENDPOINT))

            val embedded = ECKey.parse(jwt.header.jwk.toJSONObject())

            assertTrue(jwt.verify(ECDSAVerifier(embedded)))
            assertEquals(JOSEObjectType("dpop+jwt"), jwt.header.type)
            assertEquals(JWSAlgorithm.ES256, jwt.header.algorithm)
            assertEquals(key.jkt(), embedded.computeThumbprint().toString())
        }
    }

    @Test
    fun `htm and htu bind the proof to one method and one URI`() {
        runTest {
            val claims = parse(factory().proof("post", TOKEN_ENDPOINT)).jwtClaimsSet

            // Uppercased: the server compares against `Method.name`, which is uppercase, and
            // an OkHttp caller is free to pass any spelling.
            assertEquals("POST", claims.getStringClaim("htm"))
            assertEquals(TOKEN_ENDPOINT, claims.getStringClaim("htu"))
        }
    }

    @Test
    fun `htu drops the query and fragment the server also ignores`() {
        // RFC 9449 §4.3 step 9. Keeping them would not merely be redundant — the server
        // compares against its own stripped form, so the proof would simply not match.
        runTest {
            val proof = factory().proof("GET", "$EDGE_RESOURCE?page=2&q=secret#top")

            assertEquals(EDGE_RESOURCE, parse(proof).jwtClaimsSet.getStringClaim("htu"))
        }
    }

    @Test
    fun `htu keeps a percent-encoded path segment encoded`() {
        // Decoding first would collapse `/a%2Fb` (one segment) and `/a/b` (two) into the same
        // claim, letting a proof minted for one validate a request for the other. The server
        // normalises from the raw path for exactly this reason.
        runTest {
            val proof = factory().proof("GET", "https://versola.io/resources/a%2Fb")

            assertEquals("https://versola.io/resources/a%2Fb", parse(proof).jwtClaimsSet.getStringClaim("htu"))
        }
    }

    @Test
    fun `ath is present only when there is an access token to bind to`() {
        runTest {
            val atTokenEndpoint = parse(factory().proof("POST", TOKEN_ENDPOINT)).jwtClaimsSet
            val atResource = parse(factory().proof("GET", EDGE_RESOURCE, accessToken = "the-token")).jwtClaimsSet

            // The token endpoint has no token yet to hash, so `ath` there is not "omitted for
            // now" — it is impossible. A resource server requires it.
            assertNull(atTokenEndpoint.getStringClaim("ath"))
            assertEquals(ath("the-token"), atResource.getStringClaim("ath"))
        }
    }

    @Test
    fun `every proof carries a different jti`() {
        // The server records each one (`DpopProofRepository.recordIfAbsent`) and refuses a
        // repeat as a replay, so a reused jti fails the second request of every pair.
        runTest {
            val factory = factory()

            val first = parse(factory.proof("POST", TOKEN_ENDPOINT)).jwtClaimsSet.jwtid
            val second = parse(factory.proof("POST", TOKEN_ENDPOINT)).jwtClaimsSet.jwtid

            assertNotEquals(first, second)
        }
    }

    @Test
    fun `the nonce claim comes from the cache entry for that origin`() {
        runTest {
            val nonces = DpopNonceCache()
            nonces.store(TOKEN_ENDPOINT, "auth-nonce")
            val factory = factory(nonces)

            val toAuth = parse(factory.proof("POST", TOKEN_ENDPOINT)).jwtClaimsSet
            val toEdge = parse(factory.proof("GET", EDGE_RESOURCE)).jwtClaimsSet

            assertEquals("auth-nonce", toAuth.getStringClaim("nonce"))
            // Scenario 04: edge has issued nothing, so its proof carries no nonce at all.
            // Sending auth's would be refused and challenged, which is the loop.
            assertNull(toEdge.getStringClaim("nonce"))
        }
    }

    @Test
    fun `iat is stamped from server time once an offset has been learned`() {
        // Scenario 06. The device here is five minutes fast, which is past any leeway
        // `Dpop.verify` allows, so an uncorrected proof is rejected for a reason that looks
        // nothing like a clock problem from the app's side.
        runTest {
            val deviceTime = 1_700_000_000_000L + 300_000
            val factory = factory(clockSkew = ClockSkew { deviceTime })

            factory.observe(TOKEN_ENDPOINT, dateHeader = "Tue, 14 Nov 2023 22:13:20 GMT", nonceHeader = null)
            val iat = parse(factory.proof("POST", TOKEN_ENDPOINT)).jwtClaimsSet.getDateClaim("iat")

            assertEquals(1_700_000_000L, iat.toInstant().epochSecond)
        }
    }

    @Test
    fun `observe takes the nonce from a successful response too`() {
        // Learning only from challenges means paying for one rejection per origin per
        // process, when the server volunteers the answer on the way past.
        runTest {
            val factory = factory()

            factory.observe(TOKEN_ENDPOINT, dateHeader = null, nonceHeader = "volunteered")

            assertEquals("volunteered", parse(factory.proof("POST", TOKEN_ENDPOINT)).jwtClaimsSet.getStringClaim("nonce"))
        }
    }

    private fun ath(token: String): String = Base64.getUrlEncoder().withoutPadding()
        .encodeToString(MessageDigest.getInstance("SHA-256").digest(token.toByteArray(Charsets.US_ASCII)))

    @Test
    fun `a query OkHttp leaves raw does not break the proof builder`() = runTest {
        // A JSON filter in a query string is an ordinary REST idiom, and `{`, `}`, `|` and
        // `^` are characters OkHttp does not percent-encode there. java.net.URI refuses them;
        // the proof must not, and htu strips the query regardless.
        val jwt = parse(factory().proof("GET", """https://versola.io/resources/42/search?filter={"a":1}|x^y#frag"""))

        assertEquals("https://versola.io/resources/42/search", jwt.jwtClaimsSet.getStringClaim("htu"))
    }

    @Test
    fun `htu keeps the raw path and a non-default port and normalises the host's case`() = runTest {
        val jwt = parse(factory().proof("GET", "HTTPS://Versola.kz:8443/a%2Fb/c?x=1"))

        assertEquals("https://versola.kz:8443/a%2Fb/c", jwt.jwtClaimsSet.getStringClaim("htu"))
    }
    // --- audit regressions ---

    @Test
    fun `AUDIT Z4 htu lowercases the host and drops an explicit default port, as the nonce key already does`() = runTest {
        // AUDIT: Z4. htuOf keeps host case and `:443` as given while Origin.of normalises the nonce key. RFC 9449 §4.2
        // htu is the target URI; the server compares a scheme-normalised form (RFC 3986 §6.2.3), so a proof for
        // `https://Host:443/path` must read `https://host/path`. (The test `htu keeps the raw path and the port, and
        // drops userinfo nothing` above pins the opposite for host case and will need updating with the fix.)
        val claims = parse(factory().proof("GET", "https://Versola.KZ:443/resources/42?x=1")).jwtClaimsSet

        assertEquals("https://versola.kz/resources/42", claims.getStringClaim("htu"))
    }

    @Test
    fun `AUDIT Z4 htu drops userinfo`() = runTest {
        val claims = parse(factory().proof("GET", "https://user:pass@versola.kz/resources/42")).jwtClaimsSet

        assertEquals("https://versola.kz/resources/42", claims.getStringClaim("htu"))
    }

    @Test
    fun `AUDIT Z4 htu keeps a non-default port and an IPv6 literal`() = runTest {
        // Control: the normalisation must not eat what the server compares. Passes today.
        assertEquals("http://localhost:8080/a", parse(factory().proof("GET", "http://localhost:8080/a?q=1")).jwtClaimsSet.getStringClaim("htu"))
        assertEquals("https://[::1]:8443/a", parse(factory().proof("GET", "https://[::1]:8443/a")).jwtClaimsSet.getStringClaim("htu"))
    }

    @Test
    fun `AUDIT Z7 a URL the proof builder refuses does not put its query into the exception message`() = runTest {
        // AUDIT: Z7. The require(...) messages in Origin interpolate the whole URL, query included; an app
        // that logs the exception, or a crash reporter, then holds `?token=...`.
        val secret = "SECRET-QUERY-TOKEN-4f2a"
        for (url in listOf("versola.kz/path?token=$secret", "https://?token=$secret", "https://[::1/path?token=$secret")) {
            val error = runCatching { factory().proof("GET", url) }.exceptionOrNull()

            assertTrue("expected the builder to refuse $url", error is IllegalArgumentException)
            var cause: Throwable? = error
            while (cause != null) {
                assertTrue("exception text leaks the query: ${cause.message}", cause.message?.contains(secret) != true)
                cause = cause.cause
            }
        }
    }

    @Test
    fun `AUDIT Z7 the nonce cache refuses a malformed URL without echoing its query`() {
        val secret = "SECRET-QUERY-TOKEN-4f2a"
        val cache = DpopNonceCache()

        val error = runCatching { cache.nonceFor("no-scheme.example/path?token=$secret") }.exceptionOrNull()

        assertTrue(error is IllegalArgumentException)
        assertTrue("exception text leaks the query: ${error?.message}", error?.message?.contains(secret) != true)
    }

}
