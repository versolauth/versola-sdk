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

    // AUDIT: D13 (design). Because the carrier is an IOException, `catch (e: IOException)` treats a
    // revoked session as offline. Proposed: a public helper that unwraps the VersolaError from any
    // Throwable (`Throwable.versolaError(): VersolaError?`) so app code can branch first. The test
    // looks the helper up by name over the module's public facade classes, so it compiles today.
    @Test
    fun `AUDIT D13 a public helper unwraps the VersolaError from a VersolaHttpException`() {
        val candidates = listOf(
            "versola.sdk.okhttp.VersolaHttpExceptionKt",
            "versola.sdk.okhttp.VersolaErrorsKt",
            "versola.sdk.okhttp.ThrowablesKt",
            "versola.sdk.okhttp.ThrowableKt",
            "versola.sdk.okhttp.VersolaInterceptorKt",
            "versola.sdk.okhttp.VersolaHttpException",
            "versola.sdk.okhttp.VersolaHttpException\$Companion",
        )
        val helper = candidates.firstNotNullOfOrNull { name ->
            runCatching { Class.forName(name) }.getOrNull()
                ?.methods?.firstOrNull { it.name == "versolaError" }
        }
        assertTrue("no public `versolaError` helper to unwrap a VersolaError from a Throwable", helper != null)

        val refused = VersolaError.StepUp(listOf("c2"), null)
        val wrapped = VersolaHttpException(refused)
        val result = if (java.lang.reflect.Modifier.isStatic(helper!!.modifiers)) {
            helper.invoke(null, wrapped)
        } else {
            helper.invoke(helper.declaringClass.getField("INSTANCE").get(null), wrapped)
        }
        assertTrue("helper returned $result", result === refused)
    }
}
