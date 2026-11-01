import Foundation
import OAuthCore

/// The operations of ``OAuthClient`` that an app's own code calls, as a protocol, so that the code
/// is tested against ``FakeOAuthApi`` and not a live client (`spec/oauth-sdk-api.md` section 17).
/// The HTTP helpers are not here: `authenticatedSession` returns a session a fake cannot honour.
public protocol OAuthApi: Sendable {
    /// The state machine, one stream per observer; the first value is the restored state.
    func sessionStates() async -> AsyncStream<SessionState>

    /// The current state, restored first.
    var sessionState: SessionState { get async }

    /// The claims of the last validated ID token, or nil when there is no session.
    var claims: IdTokenClaims? { get async }

    func metadata() async throws -> ProviderMetadata
    func login(_ options: LoginOptions) async throws
    func stepUp(acrValues: [String], maxAge: Int?, options: LoginOptions) async throws
    func logout(_ options: LogoutOptions) async -> LogoutOutcome
    func accessToken() async throws -> AccessToken
    func refresh() async throws
    func userInfo() async throws -> UserInfo
    func keyAttestation() async throws -> KeyAttestation?
}

/// The defaults a protocol cannot declare, so that `api.login()` reads as it does on the client.
public extension OAuthApi {
    func login() async throws { try await login(.default) }
    func stepUp(acrValues: [String], maxAge: Int?) async throws {
        try await stepUp(acrValues: acrValues, maxAge: maxAge, options: .default)
    }
    func logout() async -> LogoutOutcome { await logout(.default) }
}
