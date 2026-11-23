package versola.oauth.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** `PendingAuthorizationRequest.lifetimeMillis`: a starter's own expiry, never beyond ten minutes. */
class PendingAuthorizationLifetimeTest {

    private val created = 1_000_000L

    private fun pending(lifetimeMillis: Long? = null) = PendingAuthorizationRequest(
        state = "s",
        nonce = "n",
        codeVerifier = "v",
        scopes = listOf("openid"),
        redirectUri = "https://app.example.com/oauth",
        acrValues = emptyList(),
        maxAge = null,
        createdAtEpochMillis = created,
        lifetimeMillis = lifetimeMillis ?: PendingAuthorizationRequest.MAX_AGE_MILLIS,
    )

    @Test
    fun `a request without a lifetime of its own lives ten minutes`() {
        val request = pending()

        assertEquals(PendingAuthorizationRequest.MAX_AGE_MILLIS, request.lifetimeMillis)
        assertFalse(request.isExpired(created + 10 * 60 * 1000 - 1))
        assertTrue(request.isExpired(created + 10 * 60 * 1000))
        assertEquals(10 * 60 * 1000L, request.remainingMillis(created))
    }

    @Test
    fun `a shorter lifetime expires the request at that age and not at ten minutes`() {
        val request = pending(lifetimeMillis = 60_000)

        assertFalse(request.isExpired(created + 59_999))
        assertTrue(request.isExpired(created + 60_000))
        assertTrue(request.isExpired(created + 61_000))
    }

    @Test
    fun `remaining time counts down from the shorter lifetime and stops at zero`() {
        val request = pending(lifetimeMillis = 60_000)

        assertEquals(60_000L, request.remainingMillis(created))
        assertEquals(45_000L, request.remainingMillis(created + 15_000))
        assertEquals(0L, request.remainingMillis(created + 60_000))
        assertEquals(0L, request.remainingMillis(created + 5 * 60_000))
    }

    @Test
    fun `a lifetime beyond ten minutes is capped at ten minutes`() {
        val request = pending(lifetimeMillis = 60 * 60 * 1000)

        assertFalse(request.isExpired(created + 10 * 60 * 1000 - 1))
        assertTrue(request.isExpired(created + 10 * 60 * 1000))
        assertEquals(PendingAuthorizationRequest.MAX_AGE_MILLIS, request.remainingMillis(created))
    }

    @Test
    fun `a negative lifetime is an expired request and not a long-lived one`() {
        val request = pending(lifetimeMillis = -1)

        assertTrue(request.isExpired(created))
        assertEquals(0L, request.remainingMillis(created))
    }

    @Test
    fun `a request created further ahead than the tolerance is expired whatever its lifetime`() {
        val request = pending(lifetimeMillis = 60_000)

        assertTrue(request.isExpired(created - PendingAuthorizationRequest.FUTURE_TOLERANCE_MILLIS - 1))
        assertFalse(request.isExpired(created - PendingAuthorizationRequest.FUTURE_TOLERANCE_MILLIS))
    }

    @Test
    fun `the lifetime survives the codec`() {
        val decoded = PendingAuthorizationCodec.decode(PendingAuthorizationCodec.encode(pending(lifetimeMillis = 60_000)))

        assertEquals(60_000L, decoded.lifetimeMillis)
        assertTrue(decoded.isExpired(created + 60_000))
        assertFalse(decoded.isExpired(created + 59_999))
    }

    @Test
    fun `the lifetime survives the codec beside a starter's extension`() {
        val request = PendingAuthorizationRequest(
            state = "s", nonce = "n", codeVerifier = "", scopes = listOf("openid"),
            redirectUri = "https://app.example.com/oauth", acrValues = emptyList(), maxAge = null,
            createdAtEpochMillis = created, extension = mapOf("blob" to "sealed"), issRequired = true,
            lifetimeMillis = 120_000,
        )

        val decoded = PendingAuthorizationCodec.decode(PendingAuthorizationCodec.encode(request))

        assertEquals(120_000L, decoded.lifetimeMillis)
        assertEquals(mapOf("blob" to "sealed"), decoded.extension)
        assertTrue(decoded.issRequired)
    }

    @Test
    fun `a record written without a lifetime decodes as ten minutes`() {
        val old = """{"state":"s","nonce":"n","codeVerifier":"v","scopes":["openid"],"redirectUri":"https://app.example.com/oauth","acrValues":[],"maxAge":null,"createdAtEpochMillis":1}"""

        val decoded = PendingAuthorizationCodec.decode(old.toByteArray())

        assertEquals(PendingAuthorizationRequest.MAX_AGE_MILLIS, decoded.lifetimeMillis)
    }

    @Test
    fun `a lifetime member is not mistaken for a starter's legacy artefact`() {
        // A record without an `extension` keeps its unknown string members; the lifetime is a known
        // member and a number, and must be neither dropped into the extension nor lost.
        val record = """{"state":"s","nonce":"n","codeVerifier":"v","scopes":["openid"],"redirectUri":"https://app.example.com/oauth","acrValues":[],"maxAge":null,"createdAtEpochMillis":1,"lifetimeMillis":30000,"blob":"sealed"}"""

        val decoded = PendingAuthorizationCodec.decode(record.toByteArray())

        assertEquals(30_000L, decoded.lifetimeMillis)
        assertEquals(mapOf("blob" to "sealed"), decoded.extension)
    }

    @Test
    fun `a decoded record claiming more than ten minutes is still capped`() {
        val record = """{"state":"s","nonce":"n","codeVerifier":"v","scopes":["openid"],"redirectUri":"https://app.example.com/oauth","acrValues":[],"maxAge":null,"createdAtEpochMillis":1,"lifetimeMillis":99999999999}"""

        val decoded = PendingAuthorizationCodec.decode(record.toByteArray())

        assertTrue(decoded.isExpired(1 + PendingAuthorizationRequest.MAX_AGE_MILLIS))
    }

    // ---- expectedSubject: the step-up's same-user check, persisted with the request ----

    private fun expecting(subject: String?) = PendingAuthorizationRequest(
        state = "s", nonce = "n", codeVerifier = "v", scopes = listOf("openid"),
        redirectUri = "https://app.example.com/oauth", acrValues = emptyList(), maxAge = null,
        createdAtEpochMillis = created, expectedSubject = subject,
    )

    @Test
    fun `the expected subject survives the codec`() {
        val decoded = PendingAuthorizationCodec.decode(PendingAuthorizationCodec.encode(expecting("alice")))

        assertEquals("alice", decoded.expectedSubject)
    }

    @Test
    fun `a record written without an expected subject decodes as none`() {
        val old = """{"state":"s","nonce":"n","codeVerifier":"v","scopes":["openid"],"redirectUri":"https://app.example.com/oauth","acrValues":[],"maxAge":null,"createdAtEpochMillis":1}"""

        assertNull(PendingAuthorizationCodec.decode(old.toByteArray()).expectedSubject)
        assertNull(PendingAuthorizationCodec.decode(PendingAuthorizationCodec.encode(expecting(null))).expectedSubject)
    }

    @Test
    fun `the expected subject is a known member and not a starter's legacy artefact`() {
        // Without an `extension` every unknown string member is kept in it; the subject is a string.
        val record = """{"state":"s","nonce":"n","codeVerifier":"v","scopes":["openid"],"redirectUri":"https://app.example.com/oauth","acrValues":[],"maxAge":null,"createdAtEpochMillis":1,"expectedSubject":"alice","blob":"sealed"}"""

        val decoded = PendingAuthorizationCodec.decode(record.toByteArray())

        assertEquals("alice", decoded.expectedSubject)
        assertEquals(mapOf("blob" to "sealed"), decoded.extension)
    }

    @Test
    fun `the expected subject stays out of toString`() {
        assertFalse(expecting("alice-subject").toString().contains("alice-subject"))
    }
}
