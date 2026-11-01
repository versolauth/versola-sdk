package versola.oauth.testing

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import versola.oauth.LoginOptions
import versola.oauth.LogoutOptions
import versola.oauth.OAuthApi
import versola.oauth.core.AccessToken
import versola.oauth.core.IdTokenClaims
import versola.oauth.core.LogoutOutcome
import versola.oauth.core.ProviderMetadata
import versola.oauth.core.SessionState
import versola.oauth.core.UserInfo
import versola.oauth.core.VersolaError
import versola.sdk.dpop.KeyAttestation

/**
 * A stand-in for [versola.oauth.OAuthClient] in an app's tests. It records each call by name in
 * [calls], and returns what the test scripted. It does no protocol work: no PKCE, no validation,
 * no storage. Set [error] to make the next operations fail with a category the app must handle.
 */
public class FakeOAuthApi(
    state: SessionState = SessionState.Unauthenticated,
) : OAuthApi {
    private val states = MutableStateFlow(state)

    /** The names of the operations called, in order. */
    public val calls: MutableList<String> = mutableListOf()

    /** Set to make [accessToken], [refresh], [userInfo], [login], [stepUp] and [logout] throw it. */
    public var error: VersolaError? = null

    /** The token [accessToken] returns; a bearer token by default. */
    public var token: AccessToken = AccessToken("fake-access-token", isDpopBound = false)

    /** What [logout] reports. */
    public var logoutOutcome: LogoutOutcome = LogoutOutcome(sessionEnded = true, tokenRevoked = true)

    /** What [userInfo] returns. */
    public var userInfo: UserInfo = UserInfo(subject = "fake-subject", claims = emptyMap())

    /** What [metadata] returns; a test that calls it must set this first. */
    public var metadata: ProviderMetadata? = null

    override val sessionState: Flow<SessionState> get() = states

    override var claims: IdTokenClaims? = null

    /** Moves the state the way a test needs it, without a sign-in. */
    public fun setState(state: SessionState) {
        states.value = state
    }

    override suspend fun metadata(): ProviderMetadata {
        calls += "metadata"
        return checkNotNull(metadata) { "FakeOAuthApi.metadata is not scripted" }
    }

    override suspend fun login(options: LoginOptions) {
        calls += "login"
        error?.let { throw it }
        states.value = SessionState.Authenticated
    }

    override suspend fun stepUp(challenge: VersolaError.StepUp, options: LoginOptions) {
        calls += "stepUp"
        error?.let { throw it }
        states.value = SessionState.Authenticated
    }

    override suspend fun logout(options: LogoutOptions): LogoutOutcome {
        calls += "logout"
        error?.let { throw it }
        states.value = SessionState.Unauthenticated
        claims = null
        return logoutOutcome
    }

    override suspend fun accessToken(): AccessToken {
        calls += "accessToken"
        error?.let { throw it }
        return token
    }

    override suspend fun refresh() {
        calls += "refresh"
        error?.let { throw it }
    }

    override suspend fun userInfo(): UserInfo {
        calls += "userInfo"
        error?.let { throw it }
        return userInfo
    }

    override suspend fun keyAttestation(): KeyAttestation? {
        calls += "keyAttestation"
        return null
    }
}
