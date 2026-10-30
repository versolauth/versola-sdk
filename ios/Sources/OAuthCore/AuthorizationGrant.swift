import Foundation

/// A validated authorization code with everything the token exchange needs to redeem it.
/// `AuthorizationResponseValidator.validate` is the only thing in the SDK that makes one, which
/// is the point: a code that reached the token endpoint was checked first.
package struct AuthorizationGrant: Sendable, CustomStringConvertible {
    /// The authorization code. Single use; spent by the token client.
    package let code: String
    /// The PKCE verifier the code was bound to.
    package let codeVerifier: String
    package let redirectUri: String
    /// RFC 8707 `resource` values the request carried; the exchange repeats them (section 2.2).
    package let resources: [String]
    /// What a facade's starter left on the pending request for the exchange, unchanged.
    package let extensions: [String: String]
    /// The nonce the request carried: the ID token must echo it.
    package let nonce: String
    package let scopes: [String]
    /// The `state` the redirect carried, already matched; a back channel may want it back.
    package let state: String
    /// RFC 9207 `iss` off the redirect, already matched; a back channel may require it.
    package let iss: String?
    /// The `max_age` the request carried, restored from the pending request. A login finished in
    /// another process than the one that asked has no caller to remember it, and the ID token's
    /// `auth_time` check must not depend on there being one.
    package let maxAge: Int?

    package init(
        code: String, codeVerifier: String, redirectUri: String, resources: [String] = [],
        extensions: [String: String] = [:], nonce: String = "", scopes: [String] = [],
        state: String = "", iss: String? = nil, maxAge: Int? = nil
    ) {
        self.code = code
        self.codeVerifier = codeVerifier
        self.redirectUri = redirectUri
        self.resources = resources
        self.extensions = extensions
        self.nonce = nonce
        self.scopes = scopes
        self.state = state
        self.maxAge = maxAge
        self.iss = iss
    }

    /// Credential material on several counts: never printed.
    package var description: String { "AuthorizationGrant(redacted)" }
}
