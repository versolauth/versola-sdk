package kz.versola.sdk.core

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.URI
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

/**
 * Redeems grants at the token endpoint: `authorization_code` once per login,
 * `refresh_token` for as long as the session lives.
 *
 * Deliberately no client secret anywhere in this interface or its implementation. A mobile
 * client is public (#1 §2), and a parameter that cannot be expressed cannot be shipped in an
 * APK by an integrator who was sure it would be fine.
 *
 * Single-flight coordination, the rotation slot and the retry budget are **not** here. This
 * type performs one exchange per call; what decides how many calls there are, and in what
 * order they touch storage, is the refresh coordinator above it.
 */
public interface TokenClient {

    /** Redeems a validated authorization code. The PKCE verifier goes with it. */
    public suspend fun exchange(grant: AuthorizationGrant): TokenResponse

    /**
     * Spends a refresh token. **Takes ownership of [refreshToken]** and zeroes it once the
     * request body is formed.
     *
     * @param idempotencyKey `Idempotency-Key`, which the server honours for this grant type
     *   only: losing a refresh response costs the client its session rather than one request.
     *   Derived from the generation being spent, so a retry after a dropped response resolves
     *   to the same rotation instead of reading as a replay.
     */
    public suspend fun refresh(refreshToken: ByteArray, idempotencyKey: String): TokenResponse
}

/**
 * The token endpoint over OkHttp.
 *
 * Two protocol-shaped retries live here rather than in the caller's budget, because both are
 * answers to a challenge rather than to a failure, and `spec/retry-policy.md` fixes each at
 * exactly one:
 *
 * - `use_dpop_nonce` — the nonce arrives in the response, so the second attempt is the first
 *   one that could have carried it. A second demand means a server that will never be
 *   satisfied, which is `NonceLoop` rather than a third attempt (scenario 05).
 * - `invalid_dpop_proof` — the one recoverable cause is clock skew, and the `Date` header of
 *   the rejection is what corrects it. A second failure means the key does not match the
 *   grant.
 *
 * Everything else this class raises is final: it has no budget of its own and does not sleep.
 */
public class HttpTokenClient(
    private val configuration: VersolaConfiguration,
    private val discovery: DiscoveryService,
    private val httpClient: OkHttpClient,
    /** Null for a session that is not key-bound; see [TokenBinding]. */
    private val dpop: DpopProofSource? = null,
    private val tokenBinding: TokenBinding = if (dpop == null) TokenBinding.Bearer else TokenBinding.Dpop(),
) : TokenClient {

    init {
        // The same pairing `AuthorizationFlow` refuses, for the same reason: with no proof
        // source, a key-bound request goes out unbound and `requireHardware` then checks a
        // `DPoP` token type the server can hand back regardless of whether a proof was ever
        // presented. Wiring, not deployment — it fails here rather than at the first exchange.
        if (tokenBinding is TokenBinding.Dpop && dpop == null) {
            throw VersolaError.Configuration(
                VersolaError.Configuration.Detail.InvalidConfiguration(
                    "TokenBinding.Dpop needs a DpopProofSource; pass one or select TokenBinding.Bearer",
                ),
            )
        }
    }

    override suspend fun exchange(grant: AuthorizationGrant): TokenResponse {
        val form = FormBody()
            .add("grant_type", "authorization_code")
            .add("code", grant.code)
            .add("redirect_uri", grant.redirectUri)
            .add("code_verifier", grant.codeVerifier.value)
            .add("client_id", configuration.clientId)
        return post(form, idempotencyKey = null)
    }

    override suspend fun refresh(refreshToken: ByteArray, idempotencyKey: String): TokenResponse {
        val form = FormBody()
            .add("grant_type", "refresh_token")
            // Appended as bytes and never as a String: the caller unwrapped this for the
            // duration of one request, and a String copy would outlive it until a collection
            // nobody controls (spec/state-machine.md, Locked).
            .addBytes("refresh_token", refreshToken)
            .add("client_id", configuration.clientId)
        refreshToken.fill(0)
        return post(form, idempotencyKey)
    }

    private suspend fun post(form: FormBody, idempotencyKey: String?): TokenResponse {
        val url = discovery.metadata().tokenEndpoint
        val body = form.toByteArray()
        // The encoded token exists twice for as long as the builder is alive; the copy it
        // keeps is as spendable as the one on the wire, so it goes now rather than at the
        // next collection.
        form.clear()
        try {
            var nonceRetried = false
            var proofRetried = false
            while (true) {
                when (val outcome = attempt(url, body, idempotencyKey)) {
                    is Attempt.Issued -> return outcome.response

                    is Attempt.UseDpopNonce -> {
                        // The nonce is already in the cache by now: `observe` stored it off
                        // the same response, so the retry's proof picks it up by itself.
                        //
                        // Unless the challenge carried none, which `observe` cannot cache and
                        // no retry can answer — the same unbounded loop by another route, and
                        // the line `DpopNonceRetry.accept` already draws. Terminating here
                        // also spares a code exchange a second request that can only burn the
                        // grant.
                        if (nonceRetried || outcome.nonce.isNullOrEmpty()) {
                            throw VersolaError.Recoverable(
                                VersolaError.Recoverable.Cause.NonceLoop(originOf(url)),
                            )
                        }
                        nonceRetried = true
                    }

                    is Attempt.InvalidProof -> {
                        if (proofRetried) {
                            throw VersolaError.Reauthenticate(
                                VersolaError.Reauthenticate.Reason.CredentialsInvalidated,
                            )
                        }
                        proofRetried = true
                    }
                }
            }
        } finally {
            body.fill(0)
        }
    }

    private suspend fun attempt(url: String, body: ByteArray, idempotencyKey: String?): Attempt {
        val builder = Request.Builder()
            .url(url)
            .header("Accept", "application/json")
            .post(body.toRequestBody(FORM_MEDIA_TYPE))
        idempotencyKey?.let { builder.header("Idempotency-Key", it) }
        proofFor(url)?.let { builder.header("DPoP", it) }

        return withContext(Dispatchers.IO) {
            try {
                httpClient.newCall(builder.build()).execute().use { response ->
                    val payload = response.body.string()
                    val nonce = response.header("DPoP-Nonce")
                    dpop?.observe(url, response.header("Date"), nonce)
                    if (response.isSuccessful) {
                        Attempt.Issued(issued(payload))
                    } else {
                        rejected(response.code, payload, nonce)
                    }
                }
            } catch (e: IOException) {
                throw VersolaError.Recoverable(
                    VersolaError.Recoverable.Cause.Network("token request failed: ${e.message}"),
                    e,
                )
            }
        }
    }

    /**
     * A proof goes on the request exactly when the pairing can produce one the deployment
     * will honour. Sending one to a provider that does not advertise DPoP is not harmless:
     * the server is entitled to reject an unexpected proof, and the SDK's own fallback rule
     * (#1 §4) is to run bearer there rather than to insist.
     */
    private suspend fun proofFor(url: String): String? {
        if (tokenBinding !is TokenBinding.Dpop) return null
        if (!discovery.metadata().supportsDpop) return null
        return dpop?.proof("POST", url)
    }

    private fun issued(payload: String): TokenResponse {
        val parsed = try {
            discoveryJson.decodeFromString(TokenResponsePayload.serializer(), payload)
        } catch (e: Exception) {
            throw VersolaError.Configuration(
                VersolaError.Configuration.Detail.TokenResponseMalformed(
                    e.message ?: e::class.java.simpleName,
                ),
                e,
            )
        }
        val response = TokenResponse.from(parsed)

        // A proof was sent and the server issued a bearer token anyway: the grant is not
        // key-bound, whatever the app asked for. Silent only when the app said it could live
        // without binding — `requireHardware` is the assertion that it cannot (scenario 07).
        val binding = tokenBinding
        if (binding is TokenBinding.Dpop && binding.requireHardware && !response.isDpopBound) {
            throw VersolaError.Configuration(
                VersolaError.Configuration.Detail.HardwareBindingUnavailable(
                    "the token endpoint issued a ${response.tokenType} token for a DPoP-bound request",
                ),
            )
        }
        return response
    }

    /**
     * `spec/errors.md`, token endpoint table. Mapped on the `error` value rather than on the
     * status: the status is 400 for nearly all of them, and the one that matters —
     * `invalid_grant` — shares it with six codes that mean the opposite.
     */
    private fun rejected(status: Int, payload: String, nonce: String?): Attempt {
        // 5xx is the provider having a bad moment, and its body is as likely to be an HTML
        // error page as JSON. Transport-shaped, retried under the caller's budget.
        if (status >= 500) {
            throw VersolaError.Recoverable(
                VersolaError.Recoverable.Cause.Network("token endpoint returned HTTP $status"),
            )
        }

        val error = try {
            discoveryJson.decodeFromString(TokenErrorPayload.serializer(), payload)
        } catch (e: Exception) {
            // A 4xx that is not an OAuth error response is a deployment answering something
            // other than a token endpoint at this URL.
            throw VersolaError.Configuration(
                VersolaError.Configuration.Detail.TokenRequestRejected(
                    "(no OAuth error in a HTTP $status response)",
                    e.message,
                ),
                e,
            )
        }

        return when (error.error) {
            "use_dpop_nonce" -> Attempt.UseDpopNonce(nonce)
            "invalid_dpop_proof" -> Attempt.InvalidProof

            "invalid_grant" -> throw VersolaError.Reauthenticate(
                VersolaError.Reauthenticate.Reason.GrantRejected,
            )

            else -> throw VersolaError.Configuration(
                VersolaError.Configuration.Detail.TokenRequestRejected(
                    error.error.ifBlank { "(no error code in a HTTP $status response)" },
                    error.errorDescription,
                ),
            )
        }
    }

    private fun originOf(url: String): String = with(URI(url)) { "$scheme://$authority" }

    private sealed interface Attempt {
        class Issued(val response: TokenResponse) : Attempt

        /**
         * RFC 9449 §8. The nonce the challenge carried is already cached by the time this is
         * read; it travels here as well because a challenge that carried none is answerable
         * by nothing and must not be retried.
         */
        class UseDpopNonce(val nonce: String?) : Attempt

        data object InvalidProof : Attempt
    }

    private companion object {
        private val FORM_MEDIA_TYPE = "application/x-www-form-urlencoded".toMediaType()
    }
}

/**
 * `application/x-www-form-urlencoded` assembled over bytes.
 *
 * OkHttp's own `FormBody` takes `String`s, which is the one thing the refresh token must not
 * become. Percent-encoding is applied per byte here for the same reason — `URLEncoder` would
 * want a `String` back.
 *
 * The buffer is grown by hand rather than delegated to `ByteArrayOutputStream`, whose backing
 * array is neither reachable nor zeroable: it would hold the encoded refresh token until a
 * collection nobody controls, which is the copy this whole path exists to avoid. Here every
 * array that ever held a byte of it is zeroed — the one in hand by [clear], and each one
 * outgrown along the way.
 */
internal class FormBody {
    private var buffer = ByteArray(256)
    private var length = 0

    fun add(name: String, value: String): FormBody = addBytes(name, value.toByteArray(Charsets.UTF_8))

    fun addBytes(name: String, value: ByteArray): FormBody = apply {
        if (length > 0) write('&'.code)
        encode(name.toByteArray(Charsets.UTF_8))
        write('='.code)
        encode(value)
    }

    fun toByteArray(): ByteArray = buffer.copyOf(length)

    /** Zeroes the encoded copy this builder holds. The caller owns what [toByteArray] gave it. */
    fun clear() {
        buffer.fill(0)
        length = 0
    }

    /** The array currently in use, so the zeroization test can watch one being discarded. */
    internal fun backingBytes(): ByteArray = buffer

    /**
     * HTML5's form encoding, which RFC 6749 §4.1.3 points at: unreserved characters pass,
     * everything else is percent-escaped. Space is escaped as `%20` rather than `+`, which
     * every server decodes and which does not depend on the `+` convention being honoured.
     */
    private fun encode(bytes: ByteArray) {
        for (byte in bytes) {
            val c = byte.toInt().toChar()
            if (c in 'A'..'Z' || c in 'a'..'z' || c in '0'..'9' || c in "-._~") {
                write(byte.toInt())
            } else {
                write('%'.code)
                write(HEX[(byte.toInt() ushr 4) and 0xF].code)
                write(HEX[byte.toInt() and 0xF].code)
            }
        }
    }

    private fun write(byte: Int) {
        if (length == buffer.size) {
            val grown = ByteArray(buffer.size * 2)
            buffer.copyInto(grown)
            // The array being replaced holds the same bytes as the one replacing it.
            buffer.fill(0)
            buffer = grown
        }
        buffer[length++] = byte.toByte()
    }

    private companion object {
        private const val HEX = "0123456789ABCDEF"
    }
}
