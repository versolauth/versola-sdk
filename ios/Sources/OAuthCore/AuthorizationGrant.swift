import Foundation

/// A validated authorization code with everything the token exchange needs to redeem it.
/// `AuthorizationResponseValidator.validate` is the only thing in the SDK that makes one, which
/// is the point: a code that reached the token endpoint was checked first.
public struct AuthorizationGrant: Sendable, CustomStringConvertible {
    /// The authorization code. Single use; spent by the token client.
    public let code: String
    /// The PKCE verifier the code was bound to.
    public let codeVerifier: String
    public let redirectUri: String
    /// RFC 8707 `resource` values the request carried; the exchange repeats them (section 2.2).
    public let resources: [String]
    /// What a facade's starter left on the pending request for the exchange, unchanged.
    public let extensions: [String: String]
    /// The nonce the request carried: the ID token must echo it.
    public let nonce: String
    public let scopes: [String]
    /// The `state` the redirect carried, already matched; a back channel may want it back.
    public let state: String
    /// RFC 9207 `iss` off the redirect, already matched; a back channel may require it.
    public let iss: String?

    public init(
        code: String, codeVerifier: String, redirectUri: String, resources: [String] = [],
        extensions: [String: String] = [:], nonce: String = "", scopes: [String] = [],
        state: String = "", iss: String? = nil
    ) {
        self.code = code
        self.codeVerifier = codeVerifier
        self.redirectUri = redirectUri
        self.resources = resources
        self.extensions = extensions
        self.nonce = nonce
        self.scopes = scopes
        self.state = state
        self.iss = iss
    }

    /// Credential material on several counts: never printed.
    public var description: String { "AuthorizationGrant(redacted)" }
}
