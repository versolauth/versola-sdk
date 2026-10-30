import Foundation

/// The authorization server metadata document (RFC 8414 / OpenID Connect Discovery), as far
/// as the SDK reads it. Unknown members are ignored; the three required ones default to empty
/// so that a document that omits one fails as `discoveryFieldMissing` naming the member rather
/// than as an opaque decoding error.
public struct ProviderMetadata: Sendable, Equatable, Codable {
    public var issuer: String
    public var authorizationEndpoint: String
    public var tokenEndpoint: String
    public var userinfoEndpoint: String?
    public var revocationEndpoint: String?
    public var endSessionEndpoint: String?
    public var jwksUri: String?
    public var scopesSupported: [String]
    public var responseTypesSupported: [String]
    public var grantTypesSupported: [String]
    public var codeChallengeMethodsSupported: [String]
    /// RFC 9449 §5.1: its absence is the bearer-fallback signal; its presence turns DPoP on.
    public var dpopSigningAlgValuesSupported: [String]
    /// RFC 9207: when advertised, an `iss` missing from the redirect is a hard failure.
    public var authorizationResponseIssParameterSupported: Bool
    /// RFC 9126: where a request is pushed before the browser opens. Absent means no PAR.
    public var pushedAuthorizationRequestEndpoint: String?
    public var requirePushedAuthorizationRequests: Bool
    /// OpenID Connect Discovery 3: the ID-token signing algorithms the provider uses.
    public var idTokenSigningAlgValuesSupported: [String]

    public init(
        issuer: String = "", authorizationEndpoint: String = "", tokenEndpoint: String = "",
        userinfoEndpoint: String? = nil, revocationEndpoint: String? = nil, endSessionEndpoint: String? = nil,
        jwksUri: String? = nil, scopesSupported: [String] = [], responseTypesSupported: [String] = [],
        grantTypesSupported: [String] = [], codeChallengeMethodsSupported: [String] = [],
        dpopSigningAlgValuesSupported: [String] = [], authorizationResponseIssParameterSupported: Bool = false,
        pushedAuthorizationRequestEndpoint: String? = nil, requirePushedAuthorizationRequests: Bool = false,
        idTokenSigningAlgValuesSupported: [String] = []
    ) {
        self.issuer = issuer
        self.authorizationEndpoint = authorizationEndpoint
        self.tokenEndpoint = tokenEndpoint
        self.userinfoEndpoint = userinfoEndpoint
        self.revocationEndpoint = revocationEndpoint
        self.endSessionEndpoint = endSessionEndpoint
        self.jwksUri = jwksUri
        self.scopesSupported = scopesSupported
        self.responseTypesSupported = responseTypesSupported
        self.grantTypesSupported = grantTypesSupported
        self.codeChallengeMethodsSupported = codeChallengeMethodsSupported
        self.dpopSigningAlgValuesSupported = dpopSigningAlgValuesSupported
        self.authorizationResponseIssParameterSupported = authorizationResponseIssParameterSupported
        self.pushedAuthorizationRequestEndpoint = pushedAuthorizationRequestEndpoint
        self.requirePushedAuthorizationRequests = requirePushedAuthorizationRequests
        self.idTokenSigningAlgValuesSupported = idTokenSigningAlgValuesSupported
    }

    /// DPoP is on whenever the provider advertises any signing algorithm for it.
    public var supportsDpop: Bool { !dpopSigningAlgValuesSupported.isEmpty }

    enum CodingKeys: String, CodingKey {
        case issuer
        case authorizationEndpoint = "authorization_endpoint"
        case tokenEndpoint = "token_endpoint"
        case userinfoEndpoint = "userinfo_endpoint"
        case revocationEndpoint = "revocation_endpoint"
        case endSessionEndpoint = "end_session_endpoint"
        case jwksUri = "jwks_uri"
        case scopesSupported = "scopes_supported"
        case responseTypesSupported = "response_types_supported"
        case grantTypesSupported = "grant_types_supported"
        case codeChallengeMethodsSupported = "code_challenge_methods_supported"
        case dpopSigningAlgValuesSupported = "dpop_signing_alg_values_supported"
        case authorizationResponseIssParameterSupported = "authorization_response_iss_parameter_supported"
        case pushedAuthorizationRequestEndpoint = "pushed_authorization_request_endpoint"
        case requirePushedAuthorizationRequests = "require_pushed_authorization_requests"
        case idTokenSigningAlgValuesSupported = "id_token_signing_alg_values_supported"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        issuer = try c.decodeIfPresent(String.self, forKey: .issuer) ?? ""
        authorizationEndpoint = try c.decodeIfPresent(String.self, forKey: .authorizationEndpoint) ?? ""
        tokenEndpoint = try c.decodeIfPresent(String.self, forKey: .tokenEndpoint) ?? ""
        userinfoEndpoint = try c.decodeIfPresent(String.self, forKey: .userinfoEndpoint)
        revocationEndpoint = try c.decodeIfPresent(String.self, forKey: .revocationEndpoint)
        endSessionEndpoint = try c.decodeIfPresent(String.self, forKey: .endSessionEndpoint)
        jwksUri = try c.decodeIfPresent(String.self, forKey: .jwksUri)
        scopesSupported = try c.decodeIfPresent([String].self, forKey: .scopesSupported) ?? []
        responseTypesSupported = try c.decodeIfPresent([String].self, forKey: .responseTypesSupported) ?? []
        grantTypesSupported = try c.decodeIfPresent([String].self, forKey: .grantTypesSupported) ?? []
        codeChallengeMethodsSupported = try c.decodeIfPresent([String].self, forKey: .codeChallengeMethodsSupported) ?? []
        dpopSigningAlgValuesSupported = try c.decodeIfPresent([String].self, forKey: .dpopSigningAlgValuesSupported) ?? []
        authorizationResponseIssParameterSupported = try c.decodeIfPresent(Bool.self, forKey: .authorizationResponseIssParameterSupported) ?? false
        pushedAuthorizationRequestEndpoint = try c.decodeIfPresent(String.self, forKey: .pushedAuthorizationRequestEndpoint)
        requirePushedAuthorizationRequests = try c.decodeIfPresent(Bool.self, forKey: .requirePushedAuthorizationRequests) ?? false
        idTokenSigningAlgValuesSupported = try c.decodeIfPresent([String].self, forKey: .idTokenSigningAlgValuesSupported) ?? []
    }

    /// OpenID Connect Discovery 4.3: the document must name the issuer it was fetched for, one
    /// trailing slash tolerated (Auth0, Hydra announce theirs with one); and the two endpoints.
    public func validate(configuredIssuer: String) throws {
        if issuer.isEmpty { throw OAuthError.configuration(.discoveryFieldMissing(field: "issuer")) }
        if trimSlash(issuer) != trimSlash(configuredIssuer) {
            throw OAuthError.configuration(.discoveryIssuerMismatch(configured: configuredIssuer, advertised: issuer))
        }
        if authorizationEndpoint.isEmpty { throw OAuthError.configuration(.discoveryFieldMissing(field: "authorization_endpoint")) }
        if tokenEndpoint.isEmpty { throw OAuthError.configuration(.discoveryFieldMissing(field: "token_endpoint")) }
        // The endpoints every session needs, refused where the document is read: a document served
        // over https can still name `http://` for the token endpoint, and the refresh token would
        // then be POSTed in the clear. The rest (UserInfo, revocation, sign-out, PAR) are checked
        // where they are used (`requireSecure`), so one an app never calls does not make the whole
        // provider unusable. Other origins are allowed (a CDN for `jwks_uri`, another host for
        // sign-out); the rule is the scheme.
        try Self.requireSecure("authorization_endpoint", authorizationEndpoint)
        try Self.requireSecure("token_endpoint", tokenEndpoint)
        if let jwksUri, !jwksUri.isEmpty { try Self.requireSecure("jwks_uri", jwksUri) }
    }

    /// Refuses an endpoint that is not an absolute `https` URL with a host (`http` on loopback
    /// only): `Configuration(DiscoveryMalformed)` naming the member. Called where an optional
    /// endpoint is about to be used, and by `validate` for the required ones.
    package static func requireSecure(_ name: String, _ endpoint: String) throws {
        if !isSecureEndpoint(endpoint) {
            throw OAuthError.configuration(.discoveryMalformed(detail: "\(name) must be an absolute https URL (http only on loopback)"))
        }
    }

    /// An absolute `https` URL with a host, or `http` to a loopback host: the rule the issuer is
    /// held to (`spec/oauth-sdk-api.md` section 3), so a development stack on `localhost` works.
    private static func isSecureEndpoint(_ endpoint: String) -> Bool {
        guard let components = URLComponents(string: endpoint), let scheme = components.scheme?.lowercased(),
              var host = components.host?.lowercased(), !host.isEmpty
        else { return false }
        if host.hasPrefix("[") && host.hasSuffix("]") { host = String(host.dropFirst().dropLast()) }
        if scheme == "https" { return true }
        return scheme == "http" && ["127.0.0.1", "localhost", "::1"].contains(host)
    }

    private func trimSlash(_ s: String) -> String { s.hasSuffix("/") ? String(s.dropLast()) : s }
}
