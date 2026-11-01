package versola.oauth.testing

import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import versola.oauth.LoginOptions
import versola.oauth.LogoutOptions
import versola.oauth.OAuthApi
import versola.oauth.core.SessionState
import versola.oauth.core.VersolaError

class FakeOAuthApiTest {

    @Test
    fun `login moves the state to authenticated and records the call`() = runTest {
        val api: OAuthApi = FakeOAuthApi()

        api.login(LoginOptions.Default)

        assertEquals(SessionState.Authenticated, api.sessionState.first())
        assertEquals(listOf("login"), (api as FakeOAuthApi).calls)
    }

    @Test
    fun `a scripted error is thrown from the operation the app would call`() = runTest {
        val fake = FakeOAuthApi(state = SessionState.Authenticated)
        fake.error = VersolaError.Reauthenticate(VersolaError.Reauthenticate.Reason.SessionExpired)

        assertThrows(VersolaError.Reauthenticate::class.java) {
            kotlinx.coroutines.runBlocking { fake.accessToken() }
        }
        assertEquals(listOf("accessToken"), fake.calls)
    }

    @Test
    fun `logout drops the claims and reports the scripted outcome`() = runTest {
        val fake = FakeOAuthApi(state = SessionState.Authenticated)
        val outcome = fake.logout(LogoutOptions.Default)

        assertEquals(SessionState.Unauthenticated, fake.sessionState.first())
        assertEquals(true, outcome.sessionEnded)
        assertEquals(true, outcome.tokenRevoked)
    }
}
