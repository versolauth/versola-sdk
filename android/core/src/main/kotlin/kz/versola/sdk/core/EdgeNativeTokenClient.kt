package kz.versola.sdk.core

import okhttp3.OkHttpClient

/**
 * The token endpoint through edge ([BackChannel.Edge]): `/native/complete` for the code,
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
 * The `Idempotency-Key` is forwarded too (`NativeAuthClient.ForwardedHeaders`), so the
 * refresh path keeps the same retry safety it has against auth directly.
 */
public class EdgeNativeTokenClient(
    private val configuration: VersolaConfiguration,
    edgeBaseUrl: String,
    httpClient: OkHttpClient,
    dpop: DpopProofSource,
    private val discovery: DiscoveryService,
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
            VersolaError.Configuration(VersolaError.Configuration.Detail.EdgeClientUnknown(configuration.clientId))
        } else {
            null
        }
    }

    override suspend fun exchange(grant: AuthorizationGrant): TokenResponse {
        // A grant started directly against auth carries a verifier and no blob; redeeming it
        // here would hand edge a code it did not push the request for. Wiring, not the
        // user's problem, and it fails before the code is spent on anything.
        val blob = grant.blob
        val tokenEndpoint = grant.tokenEndpoint
        val iss = grant.iss
        if (blob == null || tokenEndpoint == null) {
            throw VersolaError.Configuration(
                VersolaError.Configuration.Detail.InvalidConfiguration(
                    "the authorization was not started through edge; redeem it with HttpTokenClient",
                ),
            )
        }
        if (iss == null) {
            // Unreachable through AuthorizationResponseValidator, which requires `iss` for a
            // request started through edge; kept as a check because /native/complete does.
            throw VersolaError.Configuration(VersolaError.Configuration.Detail.IssuerMismatch(configuration.issuer, null))
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
        // what to sign for.
        endpoints.save(NativeEndpoints(tokenEndpoint, grant.revocationEndpoint ?: tokenEndpoint.replaceAfterLast('/', "revoke")))
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
                return executor.execute(tokenUrl, body, idempotencyKey, htu, onStatus = unknownClient)
                    .also(tokenBinding::acceptIssued)
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
     * What `/native/start` said, when this installation has completed a login through edge;
     * otherwise discovery's mutual-TLS aliases, which name the same listener in any
     * deployment where edge and auth agree on `external-url`; otherwise the plain endpoints,
     * which are right wherever auth terminates TLS itself. The first is edge's own
     * configuration and the others are inferences, so the order is not negotiable.
     */
    private suspend fun resolveEndpoints(): NativeEndpoints {
        endpoints.load()?.let { return it }
        val metadata = discovery.metadata()
        val aliases = metadata.mtlsEndpointAliases
        return NativeEndpoints(
            tokenEndpoint = aliases?.tokenEndpoint ?: metadata.tokenEndpoint,
            revocationEndpoint = aliases?.revocationEndpoint ?: metadata.revocationEndpoint
                ?: metadata.tokenEndpoint.replaceAfterLast('/', "revoke"),
        )
    }
}
