package versola.sdk.core

import versola.oauth.core.DpopProofSource
import versola.oauth.core.VersolaConfiguration
import java.util.Base64
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.test.runTest
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import okhttp3.OkHttpClient
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/** Proofs that carry a `jti`, `jti-1`, `jti-2`, ..., as a JWS the way a real one does. */
private class JtiProofSource : DpopProofSource {
    var minted = 0

    override suspend fun proof(method: String, url: String, accessToken: String?): String {
        minted++
        val payload = Base64.getUrlEncoder().withoutPadding().encodeToString("""{"jti":"jti-$minted","htm":"POST"}""".toByteArray())
        return "e30.$payload.sig"
    }

    override fun observe(url: String, dateHeader: String?, nonceHeader: String?) {}
}

/** The evidence that is about the request itself (a Play Integrity token), and the nonce it is made for (#423). */
class NativeStartIntegrityTest {

    private lateinit var server: MockWebServer
    private val proofs = JtiProofSource()

    @Before
    fun start() {
        server = MockWebServer().also { it.start() }
        proofs.minted = 0
    }

    @After
    fun stop() {
        server.close()
    }

    private fun hex(bytes: ByteArray) = bytes.joinToString("") { "%02x".format(it) }

    private fun starter(chain: Boolean = true, proofEvidence: NativeStartProofEvidence?) = HttpNativeAuthorizationStarter(
        configuration = VersolaConfiguration.create("https://id.versola.io", "mobile-app", "https://app.example.com/oauth"),
        edgeBaseUrl = server.url("/").toString().trimEnd('/'),
        httpClient = OkHttpClient(),
        dpop = proofs,
        attestation = if (chain) NativeStartAttestation { NativeAttestation.androidFields(listOf(byteArrayOf(1, 2, 3))) } else null,
        proofEvidence = proofEvidence,
    )

    private fun request() = NativeStartRequest("https://app.example.com/oauth", setOf("openid"), "n", emptyList(), null)

    private fun started() = MockResponse.Builder().code(200).setHeader("Content-Type", "application/json").body(
        """{"client_id":"mobile-app","request_uri":"urn:u","expires_in":60,"authorization_endpoint":"https://id.versola.io/authorize",""" +
            """"state":"s","blob":"b","token_endpoint":"https://id.versola.io:9008/token","revocation_endpoint":"https://id.versola.io:9008/revoke"}""",
    ).build()

    private fun challenge() = MockResponse.Builder().code(401)
        .setHeader("WWW-Authenticate", """DPoP error="use_dpop_nonce"""")
        .setHeader("DPoP-Nonce", "edge-nonce-1")
        .build()

    private fun fieldsOf(body: String, name: String) =
        body.split('&').map { it.substringBefore('=') to it.substringAfter('=') }.filter { it.first == name }.map { it.second }

    @Test
    fun `the nonce is the request's own hash in URL-safe base64, the vector the iOS client data hash has`() {
        // SHA-256("versola-attest-v1\nmobile-app\nJKT\nJTI") is 59241b98...b6860 on every platform; this is it as Play Integrity wants it.
        assertEquals("WSQbmHW2x309JMoj8IviluzRPxDlKl_6Pnvi5vB7aGA", NativeAttestation.integrityNonce("mobile-app", "JKT", "JTI"))
        assertFalse(NativeAttestation.integrityNonce("mobile-app", "JKT", "JTI") == NativeAttestation.integrityNonce("mobile-app", "JKT", "JTI2"))
        assertFalse(NativeAttestation.integrityNonce("mobile-app", "JKT", "JTI") == NativeAttestation.integrityNonce("mobile-app", "OTHER", "JTI"))
        assertFalse(NativeAttestation.integrityNonce("mobile-app", "JKT", "JTI") == NativeAttestation.integrityNonce("other-app", "JKT", "JTI"))
        assertEquals(43, NativeAttestation.integrityNonce("a", "b", "c").length)
    }

    @Test
    fun `the jti is read from a proof, and from nothing else`() {
        val proof = "e30." + Base64.getUrlEncoder().withoutPadding().encodeToString("""{"typ":"x","jti": "abc-123"}""".toByteArray()) + ".sig"
        assertEquals("abc-123", NativeAttestation.jtiOf(proof))
        assertNull(NativeAttestation.jtiOf("proof-1"))
        assertNull(NativeAttestation.jtiOf("a.b.c"))
        assertNull(NativeAttestation.jtiOf("e30." + Base64.getUrlEncoder().withoutPadding().encodeToString("{}".toByteArray()) + ".sig"))
    }

    @Test
    fun `the token goes with the request, beside the chain, with one platform field`() = runTest {
        server.enqueue(started())
        var asked: String? = null

        starter { jti -> asked = jti; NativeAttestation.integrityFields("tok+en/=") }.start(request())

        assertEquals("jti-1", asked)
        val body = server.takeRequest().body!!.utf8()
        assertEquals(listOf("android"), fieldsOf(body, "attestation_platform"))
        assertEquals(1, fieldsOf(body, "attestation_chain").size)
        assertEquals(listOf("tok%2Ben%2F%3D"), fieldsOf(body, "attestation_integrity_token"))
    }

    @Test
    fun `a nonce retry carries a token made for the new proof, never the first one again`() = runTest {
        server.enqueue(challenge())
        server.enqueue(started())
        val asked = mutableListOf<String>()

        starter { jti -> asked += jti; NativeAttestation.integrityFields("token-for-$jti") }.start(request())

        assertEquals(listOf("jti-1", "jti-2"), asked)
        assertEquals(listOf("token-for-jti-1"), fieldsOf(server.takeRequest().body!!.utf8(), "attestation_integrity_token"))
        assertEquals(listOf("token-for-jti-2"), fieldsOf(server.takeRequest().body!!.utf8(), "attestation_integrity_token"))
    }

    @Test
    fun `a device that cannot give a token sends the request without one, and does not fail it`() = runTest {
        server.enqueue(started())
        server.enqueue(started())

        starter { throw IllegalStateException("Play Store is not installed") }.start(request())
        starter { emptyList() }.start(request())

        assertFalse(server.takeRequest().body!!.utf8().contains("attestation_integrity_token"))
        assertFalse(server.takeRequest().body!!.utf8().contains("attestation_integrity_token"))
    }

    @Test
    fun `a caller that is cancelled stays cancelled`() = runTest {
        server.enqueue(started())
        try {
            starter { throw CancellationException("gone") }.start(request())
            throw AssertionError("no cancellation")
        } catch (expected: CancellationException) {
            assertTrue(expected.message == "gone")
        }
    }

    @Test
    fun `an app with no source for it sends what it sent before`() = runTest {
        server.enqueue(started())

        starter(proofEvidence = null).start(request())

        val body = server.takeRequest().body!!.utf8()
        assertEquals(listOf("android"), fieldsOf(body, "attestation_platform"))
        assertFalse(body.contains("attestation_integrity_token"))
        assertEquals(1, proofs.minted)
    }

    @Test
    fun `a token alone, with no key attestation, still names its platform`() = runTest {
        server.enqueue(started())

        starter(chain = false) { NativeAttestation.integrityFields("t") }.start(request())

        assertEquals(listOf("android"), fieldsOf(server.takeRequest().body!!.utf8(), "attestation_platform"))
    }
}
