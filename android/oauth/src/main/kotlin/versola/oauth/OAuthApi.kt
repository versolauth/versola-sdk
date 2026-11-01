package versola.oauth

import kotlinx.coroutines.flow.Flow
import versola.oauth.core.AccessToken
import versola.oauth.core.IdTokenClaims
import versola.oauth.core.LogoutOutcome
import versola.oauth.core.ProviderMetadata
import versola.oauth.core.SessionState
import versola.oauth.core.UserInfo
import versola.oauth.core.VersolaError
import versola.sdk.dpop.KeyAttestation

/**
 * The operations of [OAuthClient] that an app's own code calls, as an interface, so that the code
 * is tested against a fake and not a live client (`spec/oauth-sdk-api.md` section 17). The HTTP
 * helpers are not here: they return OkHttp types a fake cannot honour.
 */
public interface OAuthApi {
    /** The state machine of `spec/state-machine.md`, observable. */
    public val sessionState: Flow<SessionState>

    /** The claims of the last validated ID token, or null when there is no session. */
    public val claims: IdTokenClaims?

    /** The provider's discovery metadata. */
    public suspend fun metadata(): ProviderMetadata

    /** Signs the user in through the system browser (`spec/oauth-sdk-api.md` section 5). */
    public suspend fun login(options: LoginOptions = LoginOptions.Default)

    /** Answers an RFC 9470 step-up challenge by re-authorizing at the context it names. */
    public suspend fun stepUp(challenge: VersolaError.StepUp, options: LoginOptions = LoginOptions.Default)

    /** Ends the session on this device and, where the provider supports it, at the provider. */
    public suspend fun logout(options: LogoutOptions = LogoutOptions.Default): LogoutOutcome

    /** A token fit to send now, refreshed first if it is due. */
    public suspend fun accessToken(): AccessToken

    /** Spends the stored refresh token once, now. */
    public suspend fun refresh()

    /** The provider's UserInfo for the signed-in user. */
    public suspend fun userInfo(): UserInfo

    /** Which key tier the DPoP key reached, or null under bearer. */
    public suspend fun keyAttestation(): KeyAttestation?
}
