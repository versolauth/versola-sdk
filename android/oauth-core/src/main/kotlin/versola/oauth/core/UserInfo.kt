package versola.oauth.core

import java.io.IOException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.OkHttpClient
import okhttp3.Request

/**
 * The claims the UserInfo endpoint returned (OpenID Connect Core 5.3). [claims] holds every
 * claim as its JSON string form, or as JSON for an object or array, exactly as
 * [IdTokenClaims.all] does; [subject] is the validated `sub`.
 */
public class UserInfo(
    public val subject: String,
    public val claims: Map<String, String>,
) {
    /** Profile data is personal data; none of it goes to a log line through `toString`. */
    override fun toString(): String = "UserInfo(redacted)"
}

/** Asks the provider who the access token's user is. */
@VersolaInternalApi
public interface UserInfoClient {

    /**
     * @param tokens the session: its token is sent as `Bearer`, or as `DPoP` with a proof when
     *   it is key-bound; a bare 401 spends one renewal and one replay, then is `Reauthenticate`
     *   (`spec/errors.md`, a resource server's 401).
     * @param expectedSubject the `sub` of the validated ID token. Core 5.3.2: a UserInfo
     *   response about anyone else must not be used, so a different `sub` is refused.
     * @throws VersolaError.Configuration `ProviderUnsupported("userinfo_endpoint")` without an
     *   endpoint, `UserInfoRejected` for a `sub` mismatch or a signed response that does not
     *   verify.
     * @throws VersolaError.Reauthenticate `SessionRejected` on a 401.
     * @throws VersolaError.Recoverable `Network` on a transport failure or any other non-2xx.
     */
    public suspend fun fetch(tokens: AccessTokenSource, expectedSubject: String): UserInfo
}

/**
 * [UserInfoClient] over OkHttp.
 *
 * Redirects are off for the same reason as at the token endpoint: the request carries the
 * access token and, when bound, a proof, and neither may follow a `Location` the endpoint
 * named in discovery did not have a right to.
 *
 * No retries here. The caller's budget decides whether a transport failure is tried again
 * (`spec/retry-policy.md`); the one exception is the DPoP nonce challenge, answered once,
 * because it is a protocol step and not a retry (RFC 9449 section 9).
 *
 * @param userinfoEndpoint supplier from discovery, null when the provider has none.
 * @param dpop the proof source of a key-bound session; null for a bearer one. A bound token
 *   without a source cannot be presented and is refused as a misconfiguration.
 * @param verifier checks a signed (`application/jwt`) response against the provider's JWK
 *   Set, the same one that verifies ID tokens (`spec/oauth-sdk-api.md` section 11).
 */
@VersolaInternalApi
public class HttpUserInfoClient(
    private val userinfoEndpoint: suspend () -> String?,
    httpClient: OkHttpClient,
    private val dpop: DpopProofSource?,
    private val verifier: JwsVerifier,
) : UserInfoClient {

    private val httpClient: OkHttpClient = httpClient.newBuilder()
        .followRedirects(false)
        .followSslRedirects(false)
        .build()

    override suspend fun fetch(tokens: AccessTokenSource, expectedSubject: String): UserInfo {
        val url = userinfoEndpoint() ?: throw VersolaError.Configuration(
            VersolaError.Configuration.Detail.ProviderUnsupported("userinfo_endpoint"),
        )
        var accessToken = tokens.accessToken()
        if (accessToken.isDpopBound && dpop == null) {
            throw VersolaError.Configuration(
                VersolaError.Configuration.Detail.InvalidConfiguration(
                    "a DPoP-bound access token needs a DpopProofSource to call the UserInfo endpoint",
                ),
            )
        }
        var nonceRetried = false
        var refreshed = false
        while (true) {
            when (val outcome = attempt(url, accessToken)) {
                is Outcome.Body -> return parse(outcome, expectedSubject)
                // A bare 401 is read as an expired token: one refresh, one replay, then the
                // session is what the provider says it is (`spec/errors.md`).
                is Outcome.Rejected -> {
                    if (refreshed) throw VersolaError.Reauthenticate(VersolaError.Reauthenticate.Reason.SessionRejected)
                    refreshed = true
                    accessToken = tokens.renewAccessToken()
                }
                is Outcome.UseDpopNonce -> {
                    // `observe` already cached the nonce off this response, so the next proof
                    // carries it. A challenge without one, or a second challenge, cannot be
                    // answered by asking again.
                    if (nonceRetried || outcome.nonce.isNullOrEmpty()) {
                        throw VersolaError.Recoverable(VersolaError.Recoverable.Cause.NonceLoop(originOf(url)))
                    }
                    nonceRetried = true
                }
            }
        }
    }

    private suspend fun attempt(url: String, accessToken: AccessToken): Outcome {
        val bound = accessToken.isDpopBound

        return retrying(originOf(url)) { withContext(Dispatchers.IO) {
            // Built inside the repeated block: a DPoP proof is single-use (RFC 9449 section 11.1, a
            // resource server detects replay by `jti`), so every attempt carries a proof of its own.
            val builder = Request.Builder()
                .url(url)
                .header("Accept", "application/json, application/jwt")
                .header("Authorization", (if (bound) "DPoP " else "Bearer ") + accessToken.value)
                .get()
            if (bound) builder.header("DPoP", checkNotNull(dpop).proof("GET", url, accessToken.value))
            try {
                httpClient.newCall(builder.build()).execute().use { response ->
                    val payload = response.body.string()
                    val nonce = response.header("DPoP-Nonce")
                    dpop?.observe(url, response.header("Date"), nonce)
                    when {
                        response.isSuccessful -> Outcome.Body(
                            payload,
                            signed = response.header("Content-Type")?.toMediaTypeOrNull()
                                ?.let { it.type == "application" && it.subtype == "jwt" } == true,
                        )

                        response.code == 401 -> {
                            if (bound && wwwAuthenticateError(response.headers("WWW-Authenticate")) == "use_dpop_nonce") {
                                Outcome.UseDpopNonce(nonce)
                            } else {
                                Outcome.Rejected
                            }
                        }

                        // A transient condition is the operation's retry budget (`Server`, with the
                        // `Retry-After` of a 429 or 503); anything else is the provider refusing this
                        // request (a redirect that was not followed, a 403, a 404), which no retry
                        // changes: a Configuration fault, as on iOS.
                        ServerFault.isServerFault(response.code) -> throw ServerFault.failure(response.code, response.headers)

                        else -> throw VersolaError.Configuration(
                            VersolaError.Configuration.Detail.UserInfoRejected(
                                "userinfo answered ${response.code}",
                            ),
                        )
                    }
                }
            } catch (e: IOException) {
                throw VersolaError.Recoverable(
                    VersolaError.Recoverable.Cause.Network("userinfo request failed: ${e.message}"),
                    e,
                )
            }
        } }
    }

    private suspend fun parse(body: Outcome.Body, expectedSubject: String): UserInfo {
        val claims: JsonObject = if (body.signed) {
            try {
                verifier.verify(body.payload.trim()).payload
            } catch (e: JwsRejection) {
                throw rejected("the signed response does not verify (${e.reason})")
            }
        } else {
            try {
                Json.parseToJsonElement(body.payload) as? JsonObject
            } catch (e: Exception) {
                null
            } ?: throw rejected("the response is not a JSON object")
        }

        val subject = (claims["sub"] as? JsonPrimitive)?.takeIf { it.isString }?.content
            ?: throw rejected("sub is missing or not a string")
        // Not repeated in the message: both values identify a user.
        if (subject != expectedSubject) throw rejected("sub does not match the ID token's")

        return UserInfo(subject, claims.mapValues { (_, value) -> value.asText() })
    }

    private fun rejected(detail: String) =
        VersolaError.Configuration(VersolaError.Configuration.Detail.UserInfoRejected(detail))

    private fun JsonElement.asText(): String = if (this is JsonPrimitive) content else toString()

    private sealed interface Outcome {
        class Body(val payload: String, val signed: Boolean) : Outcome
        class UseDpopNonce(val nonce: String?) : Outcome
        object Rejected : Outcome
    }
}
