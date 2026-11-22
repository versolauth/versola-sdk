package versola.sdk.core

import versola.oauth.core.AuthorizationGrant
import versola.oauth.core.DpopProofSource
import versola.oauth.core.FormBody
import versola.oauth.core.TokenBinding
import versola.oauth.core.TokenClient
import versola.oauth.core.TokenRequestExecutor
import versola.oauth.core.TokenResponse
import versola.oauth.core.VersolaConfiguration
import versola.oauth.core.VersolaError
import versola.oauth.core.acceptIssued
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import versola.oauth.core.VersolaInternalApi

/**
 * The token endpoint through edge: `/native/complete` for the code,
 * `/native/token` for refreshes, `/native/revoke` for logout.
 *
 * Edge authenticates to auth over mutual TLS and relays auth's answer as it stands — status,
 * body, `DPoP-Nonce`, `WWW-Authenticate` — so the responses this class reads are the same
 * ones [HttpTokenClient] reads, and the same [TokenRequestExecutor] reads them. What differs
 * is where the proof is signed for: every proof here carries auth's mutual-TLS endpoint as
 * `htu`, because edge forwards it byte for byte and auth verifies it against its own URL. A
 * proof signed for edge's URL would be refused at auth as `invalid_dpop_proof`, and a
 * `use_dpop_nonce` in the relayed answer is auth's nonce, cached under auth's origin — not
 * edge's, which the authenticated client fills on API calls (scenario 04, the other way
 * round).
 *
 * The `Idempotency-Key` is forwarded too (`NativeAuthClient.ForwardedHeaders`). A native grant is
 * DPoP-bound and auth renews it in place, so the key changes nothing today; it is still sent, and
 * holds if a bound grant is ever rotated (`spec/versola-sdk-api.md` section 16).
 *
 * Every value is sent as it was received: a code, a refresh token and a blob may name the cell
 * that issued them, edge routes by that, and nothing here reads one (section 8).
 */
@VersolaInternalApi
public class EdgeNativeTokenClient(
    private val configuration: VersolaConfiguration,
    edgeBaseUrl: String,
    httpClient: OkHttpClient,
    dpop: DpopProofSource,
    private val endpoints: NativeEndpointsStore,
    private val tokenBinding: TokenBinding.Dpop = TokenBinding.Dpop(),
) : TokenClient {

    private val httpClient: OkHttpClient = httpClient.newBuilder()
        .followRedirects(false)
        .followSslRedirects(false)
        .build()

    private val executor = TokenRequestExecutor(this.httpClient, dpop)

    private val completeUrl = nativeEndpointUrl(edgeBaseUrl, "complete", configuration.clientId)
    private val tokenUrl = nativeEndpointUrl(edgeBaseUrl, "token", configuration.clientId)
    private val revokeUrl = nativeEndpointUrl(edgeBaseUrl, "revoke", configuration.clientId)

    /** Edge's 404: it fronts no such client. Named rather than left as "no OAuth error in a 404". */
    private val unknownClient: (Int) -> VersolaError? = { status ->
        if (status == 404) {
            VersolaError.Configuration(EdgeClientUnknown(configuration.clientId))
        } else {
            null
        }
    }

    override suspend fun exchange(grant: AuthorizationGrant): TokenResponse {
        // A grant started directly against auth carries a verifier and no blob; redeeming it
        // here would hand edge a code it did not push the request for. Wiring, not the
        // user's problem, and it fails before the code is spent on anything.
        val blob = grant.extension[EdgeAuthorizationStarter.BLOB]
        val tokenEndpoint = EdgeAuthorizationStarter.tokenEndpointOf(grant.extension)
        val revocationEndpoint = EdgeAuthorizationStarter.revocationEndpointOf(grant.extension)
        val iss = grant.iss
        if (blob == null || tokenEndpoint == null) {
            throw VersolaError.Configuration(
                VersolaError.Configuration.Detail.InvalidConfiguration(
                    "the authorization was not started through edge's /native/start",
                ),
            )
        }
        if (iss == null) {
            // Unreachable through AuthorizationResponseValidator, which requires `iss` for a
            // request started through edge; kept as a check because /native/complete does.
            throw VersolaError.Configuration(VersolaError.Configuration.Detail.IssuerMismatch(configuration.issuer, null))
        }
        // Both endpoints, and both `https`: they come from a record `NativeStart.validate` already
        // held to that, so anything else here is a record this flow did not write. Nothing is
        // inferred from one about the other, and the code is not spent on a proof addressed in the
        // clear.
        if (revocationEndpoint == null || !isSecureEndpoint(tokenEndpoint) || !isSecureEndpoint(revocationEndpoint)) {
            throw VersolaError.Configuration(
                VersolaError.Configuration.Detail.InvalidConfiguration(
                    "the pending authorization names no usable token and revocation endpoint",
                ),
            )
        }
        val body = FormBody()
            .add("code", grant.code)
            .add("state", grant.state)
            .add("iss", iss)
            .add("blob", blob)
            .toByteArray()
        val issued = executor.execute(completeUrl, body, idempotencyKey = null, htu = tokenEndpoint, onStatus = unknownClient)
        tokenBinding.acceptIssued(issued)
        // Remembered for the refreshes and the revocation that follow, in this process and
        // the next: a refresh does not go through /native/start and has no other way to learn
        // what to sign for. Written here, before the coordinator stores the refresh token, so a
        // grant on disk always has them beside it, and under NonCancellable for the same reason
        // the token is persisted that way: the code is spent.
        withContext(NonCancellable) {
            endpoints.save(NativeEndpoints(tokenEndpoint, revocationEndpoint))
        }
        return issued
    }

    override suspend fun refresh(refreshToken: ByteArray, idempotencyKey: String): TokenResponse {
        val form = FormBody()
            .add("grant_type", "refresh_token")
            .addBytes("refresh_token", refreshToken)
        refreshToken.fill(0)
        try {
            val htu = resolveEndpoints().tokenEndpoint
            val body = form.toByteArray()
            form.clear()
            try {
                // The answer of a refresh must not be lost to a cancelled caller, as in
                // `HttpTokenClient.refresh` (`AUDIT C1`): the caller waits for it, bounded by the
                // HTTP client's timeouts, and the coordinator persists it.
                return withContext(NonCancellable) {
                    executor.execute(tokenUrl, body, idempotencyKey, htu, onStatus = unknownClient)
                }.also(tokenBinding::acceptIssued)
            } finally {
                body.fill(0)
            }
        } finally {
            form.clear()
        }
    }

    /**
     * `/native/revoke`: edge checks the proof is signed for auth's revocation endpoint and
     * relays; auth's `/revoke` itself reads no proof. `token_type_hint` goes along as RFC
     * 7009 §2.1 suggests, though auth decides the type from the token's shape regardless.
     */
    override suspend fun revoke(refreshToken: ByteArray) {
        val form = FormBody()
            .add("token_type_hint", "refresh_token")
            .addBytes("token", refreshToken)
        refreshToken.fill(0)
        try {
            val htu = resolveEndpoints().revocationEndpoint
            val body = form.toByteArray()
            form.clear()
            try {
                executor.revoke(revokeUrl, body, htu, onStatus = unknownClient)
            } finally {
                body.fill(0)
            }
        } finally {
            form.clear()
        }
    }

    /**
     * What `/native/start` said at the login this grant came from. There is nothing to infer them
     * from when they are gone: the facade reads no discovery document. They are written before
     * the refresh token is, so a grant without them is a damaged store, and the proof a refresh
     * needs cannot be addressed: the same verdict as a DPoP key that is gone (`spec/errors.md`).
     */
    private suspend fun resolveEndpoints(): NativeEndpoints =
        endpoints.load()?.takeIf { isSecureEndpoint(it.tokenEndpoint) && isSecureEndpoint(it.revocationEndpoint) }
            ?: throw VersolaError.Reauthenticate(VersolaError.Reauthenticate.Reason.CredentialsInvalidated)
}
