import Foundation
import OAuthCore

/// The operations of ``Versola`` that an app's own code depends on, as a protocol, so that code can
/// be tested against a double the app writes (`spec/versola-sdk-api.md` section 13). Creating a
/// client, the redirect hand-off and the authenticated session stay on the concrete type: they
/// involve the browser and the network a double cannot honour. The SDK ships no fake.
public protocol VersolaApi: Sendable {
    /// The state machine, one stream per observer; the first value is the restored state.
    func sessionStates() async -> AsyncStream<SessionState>

    /// The current state, restored first.
    var sessionState: SessionState { get async }

    /// The claims of this session's ID token, or nil when there is no session.
    var claims: IdTokenClaims? { get async }

    /// Signs the user in through the system browser.
    func login(_ options: LoginOptions) async throws

    /// Answers the `OAuthError.stepUp` the authenticated session raised.
    func stepUp(_ challenge: OAuthError, options: LoginOptions?) async throws

    /// Signs out; the local wipe always happens.
    func logout(_ options: LogoutOptions) async -> LogoutOutcome

    /// Spends the refresh token now.
    func refresh() async throws

    /// Which tier the DPoP key reached.
    func keyAttestation() async throws -> KeyAttestation?
}

/// The defaults a protocol cannot declare, so that `api.login()` reads as it does on the client.
public extension VersolaApi {
    func login() async throws { try await login(LoginOptions()) }
    func stepUp(_ challenge: OAuthError) async throws { try await stepUp(challenge, options: nil) }
    func logout() async -> LogoutOutcome { await logout(LogoutOptions()) }
}
