package versola.oauth.core

/**
 * Builds what the browser opens and what must be persisted before it does, for a facade whose
 * authorization request is not the plain PKCE request [AuthorizationRequest] builds: a back
 * channel that pushes the request itself and keeps the verifier (the Versola facade's edge
 * flow), or any future starter of the same shape.
 *
 * [AuthorizationFlow] persists [StartedAuthorization.pending] and then opens
 * [StartedAuthorization.browserUri], in that order; the starter decides what the pending
 * request carries. Whatever the starter needs at the exchange goes into
 * [PendingAuthorizationRequest.extension], which the validator copies onto the grant.
 */
@VersolaInternalApi
public fun interface AuthorizationStarter {
    public suspend fun start(
        request: AuthorizationRequest,
        metadata: ProviderMetadata,
        nowEpochMillis: Long,
    ): StartedAuthorization
}

/** What [AuthorizationStarter.start] hands back: persist [pending], then open [browserUri]. */
@VersolaInternalApi
public class StartedAuthorization(
    public val pending: PendingAuthorizationRequest,
    public val browserUri: String,
)
