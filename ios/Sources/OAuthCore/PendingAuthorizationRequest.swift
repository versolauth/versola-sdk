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

    /// How long the request lives from `createdAt`, when whoever issued it said so: a starter whose
    /// back channel seals an expiry of its own (the Versola facade's edge flow, whose blob dies with
    /// the lifetime `/native/start` answers) sets it, so that a redirect arriving later is not sent to
    /// an exchange that can only be refused. Never longer than ``maxAge``, which is what a request
    /// without one gets and what a record persisted before this field existed reads as (see
    /// `init(from:)`). It is persisted with the request, because a cold-started process has no
    /// starter to ask.
    package let lifetime: TimeInterval

    /// Ten minutes: an authorization code would not outlive that either.
    package static let maxAge: TimeInterval = 600

    package init(
        state: String, nonce: String, codeVerifier: String, scopes: [String], redirectUri: String,
        acrValues: [String] = [], maxAge: Int? = nil, createdAt: Date, resources: [String] = [],
        issRequired: Bool = false, extensions: [String: String] = [:], lifetime: TimeInterval = PendingAuthorizationRequest.maxAge
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
        self.lifetime = Self.bounded(lifetime)
    }

    /// What `lifetime` is held to: at least zero, at most ten minutes. A non-finite value (a damaged
    /// record) is the shortest, not the longest: the request is refused, never kept alive by it.
    private static func bounded(_ lifetime: TimeInterval) -> TimeInterval {
        lifetime.isFinite ? min(max(lifetime, 0), maxAge) : 0
    }

    /// A record written before `lifetime` existed has none and reads as the ten minutes it always had.
    package init(from decoder: any Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        state = try values.decode(String.self, forKey: .state)
        nonce = try values.decode(String.self, forKey: .nonce)
        codeVerifier = try values.decode(String.self, forKey: .codeVerifier)
        scopes = try values.decode([String].self, forKey: .scopes)
        redirectUri = try values.decode(String.self, forKey: .redirectUri)
        acrValues = try values.decode([String].self, forKey: .acrValues)
        maxAge = try values.decodeIfPresent(Int.self, forKey: .maxAge)
        createdAt = try values.decode(Date.self, forKey: .createdAt)
        resources = try values.decode([String].self, forKey: .resources)
        issRequired = try values.decode(Bool.self, forKey: .issRequired)
        extensions = try values.decode([String: String].self, forKey: .extensions)
        lifetime = Self.bounded(try values.decodeIfPresent(TimeInterval.self, forKey: .lifetime) ?? Self.maxAge)
    }

    package func isExpired(at now: Date) -> Bool { now.timeIntervalSince(createdAt) > lifetime }

    /// What is left of the request's life at `now`: at most its lifetime, at least zero.
    package func remaining(at now: Date) -> TimeInterval {
        min(max(lifetime - now.timeIntervalSince(createdAt), 0), lifetime)
    }

    package var description: String { "PendingAuthorizationRequest(redacted)" }
}
