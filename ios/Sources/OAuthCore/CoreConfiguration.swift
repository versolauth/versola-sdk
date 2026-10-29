import Foundation

/// What the core needs of a configuration, validated by the facade (`spec/oauth-sdk-api.md`
/// section 3): the issuer identifier, the client id, the two redirect URIs. Everything else
/// is read from the provider's metadata.
public struct CoreConfiguration: Sendable, Equatable {
    /// Without a trailing slash; the discovery document is held to it (one slash tolerated)
    /// and the ID token's `iss` to the discovered value.
    public let issuer: String
    public let clientId: String
    public let redirectUri: URL
    public let postLogoutRedirectUri: URL?

    public init(issuer: String, clientId: String, redirectUri: URL, postLogoutRedirectUri: URL? = nil) {
        self.issuer = issuer.hasSuffix("/") ? String(issuer.dropLast()) : issuer
        self.clientId = clientId
        self.redirectUri = redirectUri
        self.postLogoutRedirectUri = postLogoutRedirectUri
    }
}
