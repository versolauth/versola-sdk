package versola.oauth.core

import java.io.IOException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

/**
 * Pushes the authorization request (RFC 9126) when the policy and the provider's metadata say
 * to, and opens the browser on the short `client_id` + `request_uri` URI it gets back; the
 * decision table is `spec/oauth-sdk-api.md` section 7.
 *
 * Decided at [start] from the metadata it is handed, not at construction: discovery is lazy
 * and cached, so the endpoint is not known any earlier, and a provider that starts requiring
 * PAR is noticed at the next `login()`.
 *
 * Unlike a back channel's starter this one keeps the exchange the normal one. The verifier
 * stays on the pending request and the grant carries no extension, so [HttpTokenClient] redeems
 * the code at the token endpoint as it would for the plain request. Pushing changes only what
 * crosses the browser: the parameters (`redirect_uri`, `scope`, `code_challenge`, `state`,
 * `nonce`) travel over the back channel, where the provider can refuse them before the user
 * sees a page (scenario 29).
 *
 * A public client has no credential, so the push carries none: the form is exactly what the
 * query would have been, `client_id` included. Redirects are switched off for the same reason
 * as at the token endpoint, and nothing here retries; the caller's budget decides that.
 */
@VersolaInternalApi
public class PushedAuthorizationStarter(
    private val configuration: VersolaConfiguration,
    httpClient: OkHttpClient,
    private val policy: PushedAuthorization,
) : AuthorizationStarter {

    /**
     * The injected client with redirects off. A 307 or 308 repeats the method and the body, and
     * the body is the whole authorization request; the endpoint came from discovery and is the
     * only place it may go.
     */
    private val httpClient: OkHttpClient = httpClient.newBuilder()
        .followRedirects(false)
        .followSslRedirects(false)
        .build()

    override suspend fun start(
        request: AuthorizationRequest,
        metadata: ProviderMetadata,
        nowEpochMillis: Long,
    ): StartedAuthorization {
        val advertised = metadata.pushedAuthorizationRequestEndpoint?.takeIf { it.isNotBlank() }
        // The endpoint to push to, or null for the plain request.
        val endpoint = when (policy) {
            PushedAuthorization.Never -> null
            PushedAuthorization.Required -> advertised ?: throw unsupported()
            PushedAuthorization.WhenAdvertised -> advertised
        }
        // Honoured whatever the option says: a plain request the provider will refuse is worse
        // than naming the capability that is missing. This also catches a provider that
        // requires PAR yet advertises nowhere to push to.
        if (endpoint == null) {
            if (metadata.requirePushedAuthorizationRequests) throw unsupported()
            return StartedAuthorization(
                pending = request.toPending(nowEpochMillis),
                browserUri = request.toUri(metadata.authorizationEndpoint),
            )
        }

        val requestUri = push(endpoint, request)
        return StartedAuthorization(
            // The verifier stays here: the exchange is the ordinary one.
            pending = request.toPending(nowEpochMillis),
            browserUri = withQuery(
                metadata.authorizationEndpoint,
                listOf("client_id" to configuration.clientId, "request_uri" to requestUri),
            ),
        )
    }

    private fun unsupported(): VersolaError = VersolaError.Configuration(
        VersolaError.Configuration.Detail.ProviderUnsupported("par"),
    )

    /** One POST; returns the `request_uri`, or raises before anything is persisted or opened. */
    private suspend fun push(endpoint: String, request: AuthorizationRequest): String {
        val form = FormBody()
        request.formParameters().forEach { (name, value) -> form.add(name, value) }
        val body = form.toByteArray()
        form.clear()

        val httpRequest = try {
            Request.Builder()
                .url(endpoint)
                .header("Accept", "application/json")
                .post(body.toRequestBody(FORM_MEDIA_TYPE))
                .build()
        } catch (e: IllegalArgumentException) {
            throw VersolaError.Configuration(
                VersolaError.Configuration.Detail.InvalidConfiguration(
                    "pushed_authorization_request_endpoint is not a URL: $endpoint",
                ),
                e,
            )
        }

        return withContext(Dispatchers.IO) {
            try {
                httpClient.newCall(httpRequest).execute().use { response ->
                    interpret(response.code, response.body.string())
                }
            } catch (e: IOException) {
                throw VersolaError.Recoverable(
                    VersolaError.Recoverable.Cause.Network("pushed authorization request failed: ${e.message}"),
                    e,
                )
            } finally {
                body.fill(0)
            }
        }
    }

    /**
     * RFC 9126 §2.2: 201 with `request_uri` and `expires_in`; §2.3: an error response, 400 for
     * a request the provider refuses. 200 is accepted as well, which some providers send.
     * Everything else is a deployment answering something other than a PAR endpoint, except the
     * statuses the retry policy already treats as the provider having a bad moment.
     */
    private fun interpret(status: Int, payload: String): String {
        if (status == 200 || status == 201) return requestUri(payload)
        // RFC 9126 §2.3 points at RFC 6749 §5.2, which uses 401 for `invalid_client`; some
        // providers answer 403 for a client not allowed to push. Each carries the error code
        // the app is promised in `AuthorizationRejected`.
        if (status == 400 || status == 401 || status == 403) {
            val error = try {
                discoveryJson.decodeFromString(PushedErrorPayload.serializer(), payload)
            } catch (e: Exception) {
                null
            }
            if (error != null && error.error.isNotBlank()) {
                throw VersolaError.Configuration(
                    VersolaError.Configuration.Detail.AuthorizationRejected(error.error, error.errorDescription),
                )
            }
        }
        if (status >= 500 || status == 408 || status == 429) {
            throw VersolaError.Recoverable(
                VersolaError.Recoverable.Cause.Network("PAR endpoint returned HTTP $status"),
            )
        }
        throw VersolaError.Configuration(
            VersolaError.Configuration.Detail.InvalidConfiguration("PAR endpoint answered $status"),
        )
    }

    private fun requestUri(payload: String): String {
        val parsed = try {
            discoveryJson.decodeFromString(PushedResponsePayload.serializer(), payload)
        } catch (e: Exception) {
            throw VersolaError.Configuration(
                VersolaError.Configuration.Detail.InvalidConfiguration("PAR response is not valid JSON"),
                e,
            )
        }
        val requestUri = parsed.requestUri
        val expiresIn = parsed.expiresIn
        if (requestUri.isNullOrBlank() || expiresIn == null || expiresIn <= 0) {
            throw VersolaError.Configuration(
                VersolaError.Configuration.Detail.InvalidConfiguration(
                    "PAR response lacks a request_uri or a positive expires_in",
                ),
            )
        }
        return requestUri
    }

    @Serializable
    private class PushedResponsePayload(
        @SerialName("request_uri") val requestUri: String? = null,
        @SerialName("expires_in") val expiresIn: Long? = null,
    )

    @Serializable
    private class PushedErrorPayload(
        @SerialName("error") val error: String = "",
        @SerialName("error_description") val errorDescription: String? = null,
    )

    private companion object {
        private val FORM_MEDIA_TYPE = "application/x-www-form-urlencoded".toMediaType()
    }
}
