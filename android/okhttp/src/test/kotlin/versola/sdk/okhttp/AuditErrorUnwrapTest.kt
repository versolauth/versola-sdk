package versola.sdk.okhttp

import java.io.IOException
import mockwebserver3.MockWebServer
import okhttp3.HttpUrl
import okhttp3.OkHttpClient
import okhttp3.Request
import org.junit.After
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import versola.oauth.core.AccessToken
import versola.oauth.core.AccessTokenSource
import versola.oauth.core.VersolaError

/** A source whose session is over: every token request is refused with a typed error. */
private class EndedSession(private val error: VersolaError) : AccessTokenSource {
    override suspend fun accessToken(): AccessToken = throw error
    override suspend fun renewAccessToken(): AccessToken = throw error
}

/** Audit finding D13: the taxonomy travels inside an `IOException`. */
class AuditErrorUnwrapTest {

    private lateinit var server: MockWebServer
    private lateinit var edge: HttpUrl

    @Before
    fun start() {
        server = MockWebServer()
        server.start()
        edge = server.url("/")
    }

    @After
    fun stop() {
        server.close()
    }

    private fun failureOf(error: VersolaError): Throwable {
        val client = OkHttpClient.Builder()
            .addInterceptor(VersolaInterceptor(EndedSession(error), edge, null))
            .build()
        return runCatching { client.newCall(Request.Builder().url(server.url("/resources/r/thing")).build()).execute() }
            .exceptionOrNull() ?: throw AssertionError("expected the call to fail")
    }

    // AUDIT: D13. A Retrofit/OkHttp caller sees a VersolaHttpException, an IOException, so a generic
    // `catch (e: IOException)` shows "you are offline" for Reauthenticate and StepUp. Whatever the
    // exception type, the VersolaError must be reachable through the cause chain, so a helper can
    // unwrap it. (Passes today; guards the contract the helper below relies on.)
    @Test
    fun `AUDIT D13 a session error thrown by the interceptor is reachable through the cause chain`() {
        val refused = VersolaError.Reauthenticate(VersolaError.Reauthenticate.Reason.SessionExpired)

        val thrown = failureOf(refused)

        assertTrue("an IOException is what OkHttp is prepared to receive: $thrown", thrown is IOException)
        val unwrapped = generateSequence(thrown) { it.cause }.filterIsInstance<VersolaError>().firstOrNull()
        assertTrue("the VersolaError is not in the cause chain of $thrown", unwrapped === refused)
    }

}
