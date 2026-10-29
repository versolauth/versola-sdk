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

    /**
     * Whether the starter binds the request to the DPoP key itself, so the flow must not put
     * `dpop_jkt` on the request it builds. The edge back channel does: the thumbprint reaches
     * `/par` from the proof on `/native/start`, the one place edge can verify it. A starter
     * that pushes the request as built (RFC 9126) does not, and keeps the flow's `dpop_jkt`.
     */
    public val bindsDpopKeyItself: Boolean get() = false
}

/** What [AuthorizationStarter.start] hands back: persist [pending], then open [browserUri]. */
@VersolaInternalApi
public class StartedAuthorization(
    public val pending: PendingAuthorizationRequest,
    public val browserUri: String,
)
