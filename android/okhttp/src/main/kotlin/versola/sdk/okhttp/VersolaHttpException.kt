package versola.sdk.okhttp

import java.io.IOException
import versola.oauth.core.VersolaError

/**
 * A [VersolaError] on its way out of an OkHttp call, wrapped in the one exception type OkHttp
 * is prepared to receive.
 *
 * `Interceptor.intercept` is declared `@Throws(IOException::class)`, and that is not merely a
 * Java-interop formality. `RealCall.AsyncCall.run` routes an `IOException` to
 * `Callback.onFailure`, but catches any other `Throwable` by cancelling the call, reporting a
 * substitute `IOException("canceled due to …")`, and then **rethrowing the original onto the
 * dispatcher thread** — where Android's default handler takes it as an uncaught exception and
 * kills the process. OkHttp asserts exactly this in `InterceptorTest`, and Square's guidance is
 * explicit: a custom exception thrown from an interceptor has to subclass `IOException` or it
 * is treated as an internal error.
 *
 * So the taxonomy travels inside an `IOException` rather than as one. Apps using the SDK's
 * `call()` never see this type — it is unwrapped there and the [error] is thrown on its own.
 * Apps that installed the interceptor into a client of their own do, and reach the same value
 * through [error].
 */
public class VersolaHttpException(
    public val error: VersolaError,
) : IOException(error.message, error)
