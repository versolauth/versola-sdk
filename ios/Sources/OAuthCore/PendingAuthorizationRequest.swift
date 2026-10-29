import Foundation

/// What is persisted before the browser opens, so that a redirect arriving at a cold-started
/// process can be validated and the code exchanged exactly as in a live one (scenario 12).
/// The code verifier is a secret: `description` redacts it, and the store wraps the record.
package struct PendingAuthorizationRequest: Sendable, Equatable, Codable, CustomStringConvertible {
    package let state: String
    package let nonce: String
    package let codeVerifier: String
    package let scopes: [String]
    package let redirectUri: String
    package let acrValues: [String]
    package let maxAge: Int?
    package let createdAt: Date
    /// RFC 8707 `resource` values, repeated on the token request.
    package let resources: [String]
    /// RFC 9207: an `iss` missing from the redirect is a hard failure when the provider
    /// advertised support at the time the request was built.
    package let issRequired: Bool
    /// What a facade's starter attached (an edge blob, its endpoints); the core keeps it opaque.
    package let extensions: [String: String]

    /// Ten minutes: an authorization code would not outlive that either.
    package static let maxAge: TimeInterval = 600

    package init(
        state: String, nonce: String, codeVerifier: String, scopes: [String], redirectUri: String,
        acrValues: [String] = [], maxAge: Int? = nil, createdAt: Date, resources: [String] = [],
        issRequired: Bool = false, extensions: [String: String] = [:]
    ) {
        self.state = state
        self.nonce = nonce
        self.codeVerifier = codeVerifier
        self.scopes = scopes
        self.redirectUri = redirectUri
        self.acrValues = acrValues
        self.maxAge = maxAge
        self.createdAt = createdAt
        self.resources = resources
        self.issRequired = issRequired
        self.extensions = extensions
    }

    package func isExpired(at now: Date) -> Bool { now.timeIntervalSince(createdAt) > Self.maxAge }

    package var description: String { "PendingAuthorizationRequest(redacted)" }
}
