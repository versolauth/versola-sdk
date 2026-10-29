package versola.sdk.okhttp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class AuthenticateChallengeTest {

    @Test
    fun `a step-up is read from the error value under the Bearer scheme edge actually sends`() {
        val challenge = AuthenticateChallenge.parse(
            listOf(
                """Bearer error="insufficient_user_authentication", """ +
                    """acr_values="urn:versola:otp urn:versola:passkey", max_age="300"""",
            ),
        )

        assertEquals("insufficient_user_authentication", challenge.error)
        assertEquals(listOf("urn:versola:otp", "urn:versola:passkey"), challenge.acrValues)
        assertEquals(300L, challenge.maxAge)
    }

    @Test
    fun `a nonce demand under the DPoP scheme reads identically, because the scheme is not read`() {
        assertEquals(
            "use_dpop_nonce",
            AuthenticateChallenge.parse(listOf("""DPoP error="use_dpop_nonce"""")).error,
        )
        assertEquals(
            "use_dpop_nonce",
            AuthenticateChallenge.parse(listOf("""Bearer error="use_dpop_nonce"""")).error,
        )
    }

    @Test
    fun `a bare 401 carries no error, which is what sends it down the refresh path`() {
        assertNull(AuthenticateChallenge.parse(emptyList()).error)
        assertNull(AuthenticateChallenge.parse(listOf("Bearer")).error)
    }

    @Test
    fun `an unparseable max_age drops that parameter rather than the whole challenge`() {
        val challenge = AuthenticateChallenge.parse(
            listOf("""Bearer error="insufficient_user_authentication", acr_values="a", max_age="soon""""),
        )

        assertEquals(listOf("a"), challenge.acrValues)
        assertNull(challenge.maxAge)
    }

    @Test
    fun `unquoted parameter values are accepted, as RFC 9110 permits`() {
        val challenge = AuthenticateChallenge.parse(listOf("Bearer error=use_dpop_nonce, max_age=60"))

        assertEquals("use_dpop_nonce", challenge.error)
        assertEquals(60L, challenge.maxAge)
    }

    @Test
    fun `parameters spread across repeated headers are read as one set`() {
        val challenge = AuthenticateChallenge.parse(
            listOf("""Bearer error="insufficient_user_authentication"""", """Bearer acr_values="a b""""),
        )

        assertEquals("insufficient_user_authentication", challenge.error)
        assertEquals(listOf("a", "b"), challenge.acrValues)
    }

    @Test
    fun `acr_values splits on spaces and drops the empty runs a doubled space leaves`() {
        assertEquals(
            listOf("a", "b"),
            AuthenticateChallenge.parse(listOf("""Bearer acr_values=" a  b """")).acrValues,
        )
    }
}
