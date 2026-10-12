package kz.versola.sdk.okhttp

import java.io.IOException
import kotlinx.coroutines.runBlocking
import kz.versola.sdk.core.AccessToken
import kz.versola.sdk.core.AccessTokenSource
import kz.versola.sdk.core.DpopProofSource
import kz.versola.sdk.core.VersolaError
import okhttp3.HttpUrl
import okhttp3.Interceptor
import okhttp3.Request
import okhttp3.Response

/**
 * The authenticated leg of #9: a token on every request to edge, a DPoP proof over it, and the
 * four things a 401 from edge can mean.
 *
 * An **application** interceptor, not a network one. A network interceptor runs once per
 * network request — redirects and OkHttp's own retries included — so its `htu` would be minted
 * for a URL that is no longer the one being called. This runs once per call, which is also the
 * unit `spec/retry-policy.md` calls one operation.
 *
 * No retry budget of its own. Every repeat it performs is one of the fixed protocol ceilings —
 * one nonce retry, one proof retry, one replay after a refresh — and the refresh it triggers
 * spends the session coordinator's budget rather than opening a second one beside it. Transport
 * failures are OkHttp's `retryOnConnectionFailure` to handle, below this layer.
 *
 * Constructed by `Versola.interceptor()` for the ordinary case. The constructor is public for
 * the wiring that does not go through the facade — a conformance harness, an app assembling the
 * modules itself — and takes exactly the three things the behaviour needs.
 */
public class VersolaInterceptor(
    private val tokens: AccessTokenSource,
    /** Requests outside this origin and path prefix are passed through untouched. */
    private val edgeBaseUrl: HttpUrl,
    /** Null under `TokenBinding.Bearer`, and then no proof goes on any request. */
    private val dpop: DpopProofSource?,
) : Interceptor {

    override fun intercept(chain: Interceptor.Chain): Response {
        val request = chain.request()
        // Anything outside edge passes through untouched, which is what makes this safe to
        // install on the same `OkHttpClient` the token endpoint and discovery use: without
        // the check, a refresh triggered here would re-enter here, and attaching an access
        // token to the request that exists to obtain one is the recursion that follows.
        if (!request.url.isUnder(edgeBaseUrl)) return chain.proceed(request)

        // The coordinator's API is suspending and OkHttp's is not, so one of the two has to
        // block. It is safe here for a reason worth stating: `HttpTokenClient` issues its
        // requests with `execute()`, and OkHttp's `Dispatcher` caps concurrency for
        // `enqueue`d calls only — sixty-four application calls blocked on a refresh therefore
        // cannot starve the refresh they are waiting for.
        return try {
            runBlocking { authenticated(chain, request) }
        } catch (e: VersolaHttpException) {
            throw e
        } catch (e: IOException) {
            throw e
        } catch (e: Throwable) {
            // Anything else leaving an interceptor is rethrown by OkHttp onto its dispatcher
            // thread for an enqueued call, where Android's default handler ends the process.
            // A Keystore refusing a key, a DataStore refusing a second instance, a URL the
            // proof builder could not parse: SDK or deployment defects every one, and reported
            // as such — never as a crash the app had no way to catch.
            throw VersolaHttpException(
                VersolaError.Configuration(
                    VersolaError.Configuration.Detail.InvalidConfiguration("unexpected failure in the authenticated client: ${e::class.java.name}: ${e.message}"),
                    e,
                ),
            )
        }
    }

    private suspend fun authenticated(chain: Interceptor.Chain, request: Request): Response {
        var token = translating { tokens.accessToken() }
        var nonceRetried = false
        var proofRetried = false
        var refreshed = false

        while (true) {
            val response = chain.proceed(sign(request, token))
            dpop?.observe(
                request.url.toString(),
                response.header("Date"),
                response.header("DPoP-Nonce"),
            )
            if (response.code != 401) return response

            val challenge = AuthenticateChallenge.parse(response.headers("WWW-Authenticate"))
            when (challenge.error) {
                // §9. `observe` has already cached the nonce off this very response, so the
                // next proof picks it up unasked. A challenge carrying none is answerable by
                // nothing, and retrying it is the unbounded loop by another route that
                // scenario 05 exists to rule out — the same line `DpopNonceRetry` draws.
                "use_dpop_nonce" -> {
                    if (nonceRetried || response.header("DPoP-Nonce").isNullOrEmpty()) {
                        response.close()
                        throw VersolaHttpException(
                            VersolaError.Recoverable(
                                VersolaError.Recoverable.Cause.NonceLoop(request.url.origin()),
                            ),
                        )
                    }
                    nonceRetried = true
                }

                // §7.1. The one recoverable cause is clock skew, which `observe` has just
                // corrected from this response's `Date`. A second refusal means the key does
                // not match the grant, and no refresh can repair that: a refresh reuses the
                // same key.
                "invalid_dpop_proof" -> {
                    if (proofRetried) {
                        response.close()
                        throw VersolaHttpException(
                            VersolaError.Reauthenticate(
                                VersolaError.Reauthenticate.Reason.CredentialsInvalidated,
                            ),
                        )
                    }
                    proofRetried = true
                }

                // RFC 9470, and deliberately the first branch that does *not* refresh. The
                // token is valid; its authentication context is not, and a refresh produces
                // another token with the same `acr` — which is how a naive client turns one
                // 401 into an unbounded rotation loop.
                "insufficient_user_authentication" -> {
                    response.close()
                    tokens.stepUpRequired()
                    throw VersolaHttpException(
                        VersolaError.StepUp(challenge.acrValues, challenge.maxAge),
                    )
                }

                // A bare 401, or a code this SDK does not know. Read as an expiry: one
                // refresh, one replay, and a second 401 is the session being refused rather
                // than the token being old.
                else -> {
                    if (refreshed) {
                        response.close()
                        throw VersolaHttpException(
                            VersolaError.Reauthenticate(
                                VersolaError.Reauthenticate.Reason.SessionRejected,
                            ),
                        )
                    }
                    refreshed = true
                    // A concurrent call on the same stale token may have already refreshed
                    // and updated the cache while this response was in flight. Rotating
                    // again here would spend a second rotation for a token that is already
                    // usable, so the cache is checked first and a new grant is forced only
                    // if it still holds the token that was just refused.
                    val cached = translating { tokens.accessToken() }
                    token = if (cached.value != token.value) {
                        cached
                    } else {
                        translating { tokens.renewAccessToken() }
                    }
                    // A one-shot or duplex body cannot be sent twice, so the refreshed token
                    // lands in the cache and this 401 is returned as it stands. The app's own
                    // retry of the operation then succeeds, having rebuilt the body it is the
                    // only party able to rebuild. Replaying a consumed body instead would
                    // fail for a reason that looks nothing like its cause.
                    if (!request.isReplayable()) return response
                }
            }
            response.close()
        }
    }

    /**
     * `Authorization`, and the proof that goes with it.
     *
     * The scheme follows the token rather than the configuration: RFC 9449 §5 makes `DPoP` the
     * scheme a key-bound token must be presented under, and `EdgeService.extractAccessToken`
     * refuses a token carrying `cnf.jkt` over `Bearer` regardless of what the deployment's
     * DPoP enforcement is set to.
     */
    private suspend fun sign(request: Request, token: AccessToken): Request {
        val builder = request.newBuilder()
        val bound = token.isDpopBound && dpop != null
        builder.header("Authorization", "${if (bound) "DPoP" else "Bearer"} ${token.value}")
        if (bound) {
            builder.header(
                "DPoP",
                // `ath` over the token actually being sent, per §4.2. The factory derives
                // `htu` from this URL and the nonce from its own cache, which is keyed by
                // origin — so edge's nonce is used here and auth's is left untouched
                // (scenario 04). Wrapped in `translating`: a `VersolaError` here (an
                // unusable key, a signing failure) must reach the caller as a
                // `VersolaHttpException` like every other taxonomy error this interceptor
                // raises, not escape raw onto OkHttp's dispatcher thread.
                translating {
                    checkNotNull(dpop).proof(request.method, request.url.toString(), token.value)
                },
            )
        }
        return builder.build()
    }

    /**
     * Raises the taxonomy in the form OkHttp can carry. Anything that is not a [VersolaError]
     * is left alone: it is not this layer's to reclassify.
     */
    private inline fun <T> translating(block: () -> T): T = try {
        block()
    } catch (e: VersolaError) {
        throw VersolaHttpException(e)
    }
}

/**
 * Whether [this] addresses the deployment's edge, by origin and by path prefix.
 *
 * The prefix matters: an integrator whose edge is `https://versola.kz` and whose own API is
 * `https://versola.kz/internal` gets a token on the first and not the second. Compared on
 * whole path segments, so `/resources` does not claim `/resources-admin`.
 */
private fun HttpUrl.isUnder(base: HttpUrl): Boolean {
    if (scheme != base.scheme || host != base.host || port != base.port) return false
    val prefix = base.encodedPath.trimEnd('/')
    return prefix.isEmpty() || encodedPath == prefix || encodedPath.startsWith("$prefix/")
}

private fun HttpUrl.origin(): String = "$scheme://$host:$port"

/**
 * Whether the request may be sent a second time.
 *
 * A one-shot body may be read once and a duplex body is written while the response is being
 * read; neither survives a replay. Most bodies are neither, so the replay after a refresh is
 * the normal path rather than the exception.
 */
private fun Request.isReplayable(): Boolean {
    val body = body ?: return true
    return !body.isOneShot() && !body.isDuplex()
}
