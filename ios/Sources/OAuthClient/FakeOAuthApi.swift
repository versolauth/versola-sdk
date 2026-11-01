import Foundation
import OAuthCore

/// A stand-in for ``OAuthClient`` in an app's tests. It records each call by name in ``calls``,
/// and returns what the test scripted. It does no protocol work: no PKCE, no validation, no
/// storage. Set ``error`` to make the next operations fail with a category the app must handle.
public actor FakeOAuthApi: OAuthApi {
    private var current: SessionState
    private var observers: [UUID: AsyncStream<SessionState>.Continuation] = [:]

    /// The names of the operations called, in order.
    public private(set) var calls: [String] = []

    /// Makes the operations that can fail throw this error.
    public var error: OAuthError?

    /// The token ``accessToken()`` returns; a bearer token by default.
    public var token = AccessToken(value: "fake-access-token", tokenType: "Bearer")

    /// What ``logout(_:)`` reports.
    public var logoutOutcome = LogoutOutcome(sessionEnded: true, tokenRevoked: true)

    /// What ``userInfo()`` returns.
    public var userInfoResult = UserInfo(subject: "fake-subject", claims: [:])

    /// What ``metadata()`` returns; a test that calls it must set this first.
    public var providerMetadata: ProviderMetadata?

    /// The claims the fake reports; nil when there is no session.
    public var claims: IdTokenClaims?

    public init(state: SessionState = .unauthenticated) {
        current = state
    }

    public func sessionStates() -> AsyncStream<SessionState> {
        let (stream, continuation) = AsyncStream.makeStream(of: SessionState.self)
        let id = UUID()
        observers[id] = continuation
        continuation.yield(current)
        continuation.onTermination = { _ in
            Task { await self.forget(id) }
        }
        return stream
    }

    public var sessionState: SessionState { current }

    /// Makes the operations that can fail throw `error`.
    public func setError(_ error: OAuthError?) {
        self.error = error
    }

    /// Moves the state the way a test needs it, without a sign-in.
    public func setState(_ state: SessionState) {
        current = state
        for continuation in observers.values { continuation.yield(state) }
    }

    public func metadata() throws -> ProviderMetadata {
        calls.append("metadata")
        guard let providerMetadata else { throw OAuthError.configuration(.invalidConfiguration(detail: "FakeOAuthApi.providerMetadata is not scripted")) }
        return providerMetadata
    }

    public func login(_ options: LoginOptions) throws {
        calls.append("login")
        try throwScripted()
        setState(.authenticated)
    }

    public func stepUp(acrValues: [String], maxAge: Int?, options: LoginOptions) throws {
        calls.append("stepUp")
        try throwScripted()
        setState(.authenticated)
    }

    /// Ends the session whatever ``error`` says: the real `logout` never throws for a server failure.
    public func logout(_ options: LogoutOptions) -> LogoutOutcome {
        calls.append("logout")
        claims = nil
        setState(.unauthenticated)
        return logoutOutcome
    }

    public func accessToken() throws -> AccessToken {
        calls.append("accessToken")
        try throwScripted()
        return token
    }

    public func refresh() throws {
        calls.append("refresh")
        try throwScripted()
    }

    public func userInfo() throws -> UserInfo {
        calls.append("userInfo")
        try throwScripted()
        return userInfoResult
    }

    public func keyAttestation() -> KeyAttestation? {
        calls.append("keyAttestation")
        return nil
    }

    private func throwScripted() throws {
        if let error { throw error }
    }

    private func forget(_ id: UUID) {
        observers[id] = nil
    }
}
