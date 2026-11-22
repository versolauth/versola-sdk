package versola.sdk

import kotlinx.coroutines.flow.Flow
import versola.oauth.core.IdTokenClaims
import versola.oauth.core.LogoutOutcome
import versola.oauth.core.SessionState
import versola.oauth.core.VersolaError
import versola.sdk.dpop.KeyAttestation

/**
 * The operations of [Versola] that an app's own code depends on, as an interface, so that code
 * can be tested against a double the app writes (`spec/versola-sdk-api.md` section 13). Creating
 * a client and the HTTP helpers stay on the concrete type: they return platform types a double
 * cannot honour. The SDK ships no fake.
 */
public interface VersolaApi {
    public val sessionState: Flow<SessionState>
    public suspend fun currentSessionState(): SessionState
    public val claims: IdTokenClaims?
    public suspend fun login(options: LoginOptions = LoginOptions())
    public suspend fun stepUp(challenge: VersolaError.StepUp, options: LoginOptions? = null)
    public suspend fun logout(options: LogoutOptions = LogoutOptions()): LogoutOutcome
    public suspend fun refresh()
    public suspend fun keyAttestation(): KeyAttestation?
}
