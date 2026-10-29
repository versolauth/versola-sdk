import CryptoKit
import Foundation

/// The endpoints of a provider that publishes no discovery document, or publishes it where the
/// SDK will not look (`spec/oauth-sdk-api.md` section 3). Every URL is `https` (`http` only on
/// a loopback host). A capability not listed is absent: no `revocationEndpoint` means sign-out
/// skips revocation, no `pushedAuthorizationRequestEndpoint` means the plain request.
public struct ProviderEndpoints: Sendable, Equatable {
    /// What the ID token's `iss` must equal, byte for byte.
    public let issuer: String
    public let authorizationEndpoint: String
    public let tokenEndpoint: String
    /// Where the ID-token signing keys are. Required: an ID token that cannot be verified is refused.
    public let jwksUri: String
    public let userinfoEndpoint: String?
    public let revocationEndpoint: String?
    public let endSessionEndpoint: String?
    public let pushedAuthorizationRequestEndpoint: String?
    /// `id_token_signing_alg_values_supported`; empty means the closed set of section 11 as a whole.
    public let idTokenSigningAlgValuesSupported: [String]

    public init(
        issuer: String, authorizationEndpoint: String, tokenEndpoint: String, jwksUri: String,
        userinfoEndpoint: String? = nil, revocationEndpoint: String? = nil, endSessionEndpoint: String? = nil,
        pushedAuthorizationRequestEndpoint: String? = nil, idTokenSigningAlgValuesSupported: [String] = []
    ) {
        self.issuer = issuer
        self.authorizationEndpoint = authorizationEndpoint
        self.tokenEndpoint = tokenEndpoint
        self.jwksUri = jwksUri
        self.userinfoEndpoint = userinfoEndpoint
        self.revocationEndpoint = revocationEndpoint
        self.endSessionEndpoint = endSessionEndpoint
        self.pushedAuthorizationRequestEndpoint = pushedAuthorizationRequestEndpoint
        self.idTokenSigningAlgValuesSupported = idTokenSigningAlgValuesSupported
    }

    /// The metadata discovery would have produced. The three capability lists are what a
    /// provider without discovery is assumed to support: code flow with PKCE S256, refresh.
    public func toMetadata() -> ProviderMetadata {
        ProviderMetadata(
            issuer: issuer, authorizationEndpoint: authorizationEndpoint, tokenEndpoint: tokenEndpoint,
            userinfoEndpoint: userinfoEndpoint, revocationEndpoint: revocationEndpoint,
            endSessionEndpoint: endSessionEndpoint, jwksUri: jwksUri,
            responseTypesSupported: ["code"], grantTypesSupported: ["authorization_code", "refresh_token"],
            codeChallengeMethodsSupported: ["S256"],
            pushedAuthorizationRequestEndpoint: pushedAuthorizationRequestEndpoint,
            idTokenSigningAlgValuesSupported: idTokenSigningAlgValuesSupported
        )
    }

    fileprivate var namedURLs: [(String, String?)] {
        [
            ("issuer", issuer), ("authorizationEndpoint", authorizationEndpoint), ("tokenEndpoint", tokenEndpoint),
            ("jwksUri", jwksUri), ("userinfoEndpoint", userinfoEndpoint), ("revocationEndpoint", revocationEndpoint),
            ("endSessionEndpoint", endSessionEndpoint),
            ("pushedAuthorizationRequestEndpoint", pushedAuthorizationRequestEndpoint),
        ]
    }
}

/// What the client is created with (`spec/oauth-sdk-api.md` section 3). Validated eagerly: a bad
/// value is `Configuration(InvalidConfiguration)` here, not behind a login screen.
///
/// There is no `clientSecret`, on purpose: a native app cannot keep one (RFC 8252 section 8.5),
/// so the type does not let an integrator pretend otherwise.
public struct OAuthConfiguration: Sendable {
    /// The issuer whose discovery document configures everything else. Exclusive with `endpoints`.
    public let issuer: String?
    /// Explicit endpoints for a provider without discovery. Exclusive with `issuer`.
    public let endpoints: ProviderEndpoints?
    public let clientId: String
    /// A verified `https` link (preferred), a loopback URI, or a private-use scheme (warned about).
    public let redirectUri: String
    /// Where RP-initiated logout sends the browser; not sent when absent.
    public let postLogoutRedirectUri: String?
    /// The scopes `login()` asks for unless its options say otherwise; `openid` is always included.
    public let scopes: Set<String>
    /// Bearer unless the resource servers verify DPoP (section 9).
    public let tokenBinding: TokenBinding
    /// Push the request when the provider advertises an endpoint for it (section 7).
    public let pushedAuthorization: PushedAuthorization
    /// The only origins the authenticated session sends a token to, `scheme://host[:port]`.
    public let protectedOrigins: Set<String>
    /// Replaces the discovered `end_session_endpoint`, or supplies one when discovery has none.
    public let endSessionEndpoint: String?
    public let retryPolicy: RetryPolicy
    public let unlockPolicy: UnlockPolicy
    /// Tolerance for `exp`, `iat` and `auth_time` in ID-token validation; at most five minutes.
    public let clockSkewTolerance: TimeInterval
    public let logger: any OAuthLogger
    /// The session the SDK's own requests go through; its timeouts and caches are the app's.
    /// Redirects are never followed on the SDK's own requests whatever the session does.
    public let urlSession: URLSession

    /// The issuer the ID token's `iss` is held to, whichever way it was configured, without a trailing slash.
    public let issuerIdentifier: String
    /// The scopes as they are sent: the configured set, with `openid` present.
    public let effectiveScopes: Set<String>
    /// What the protocol core is configured with.
    package let core: CoreConfiguration
    /// Non-nil exactly when the redirect URI is a private-use scheme, which any app on the device
    /// may also register. The client logs it as a warning on every create.
    public let redirectUriWarning: String?
    /// What keeps one client's storage apart from another's in the same app: the issuer and the
    /// client id, hashed. Two configurations with the same key must be the same configuration.
    public let storageKey: String
    /// Everything that makes two configurations the same client, excluding the session and the
    /// logger, by value: two configurations built separately with equal values are equal.
    public let fingerprint: String

    static let storageKeyLength = 16

    /// Throws `OAuthError.configuration(.invalidConfiguration)` naming the first offending field.
    public init(
        issuer: String? = nil,
        endpoints: ProviderEndpoints? = nil,
        clientId: String,
        redirectUri: String,
        postLogoutRedirectUri: String? = nil,
        scopes: Set<String> = ["openid"],
        tokenBinding: TokenBinding = .bearer,
        pushedAuthorization: PushedAuthorization = .whenAdvertised,
        protectedOrigins: Set<String> = [],
        endSessionEndpoint: String? = nil,
        retryPolicy: RetryPolicy = .default,
        unlockPolicy: UnlockPolicy = .none,
        clockSkewTolerance: TimeInterval = 60,
        logger: any OAuthLogger = OSLogLogger(),
        urlSession: URLSession = .shared
    ) throws {
        if (issuer == nil) == (endpoints == nil) {
            throw URLRules.invalid("exactly one of issuer and endpoints must be given")
        }
        for (name, url) in endpoints?.namedURLs ?? [] {
            if let url { try URLRules.requireHttps(name, url) }
        }
        if let endSessionEndpoint { try URLRules.requireHttps("endSessionEndpoint", endSessionEndpoint) }
        for origin in protectedOrigins { _ = try URLRules.parseOrigin(origin, name: "protectedOrigins") }
        if !(0...300).contains(clockSkewTolerance) {
            throw URLRules.invalid("clockSkewTolerance must be between 0 and 300 seconds: \(clockSkewTolerance)")
        }
        for scope in scopes where !URLRules.isScopeToken(scope) {
            throw URLRules.invalid("a scope is a single token without whitespace")
        }

        // Issuer, client id and redirect URIs: the checks the core's configuration owns on Android.
        let rawIssuer = issuer ?? endpoints?.issuer ?? ""
        try URLRules.requireIssuer(rawIssuer)
        if clientId.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            throw URLRules.invalid("clientId must not be blank")
        }
        let redirect = try URLRules.parseRedirect(redirectUri, name: "redirectUri")
        let postLogout = try postLogoutRedirectUri.map { try URLRules.parseRedirect($0, name: "postLogoutRedirectUri") }

        var trimmedIssuer = rawIssuer
        while trimmedIssuer.hasSuffix("/") { trimmedIssuer.removeLast() }

        self.issuer = issuer
        self.endpoints = endpoints
        self.clientId = clientId
        self.redirectUri = redirectUri
        self.postLogoutRedirectUri = postLogoutRedirectUri
        self.scopes = scopes
        self.tokenBinding = tokenBinding
        self.pushedAuthorization = pushedAuthorization
        self.protectedOrigins = protectedOrigins
        self.endSessionEndpoint = endSessionEndpoint
        self.retryPolicy = retryPolicy
        self.unlockPolicy = unlockPolicy
        self.clockSkewTolerance = clockSkewTolerance
        self.logger = logger
        self.urlSession = urlSession

        self.issuerIdentifier = trimmedIssuer
        self.effectiveScopes = scopes.union(["openid"])
        self.core = CoreConfiguration(
            issuer: trimmedIssuer, clientId: clientId, redirectUri: redirect.url, postLogoutRedirectUri: postLogout?.url
        )
        self.redirectUriWarning = redirect.kind == .customScheme
            ? "redirectUri uses a private-use scheme. Any app on this device can register the same scheme and receive the authorization response. Prefer a verified universal link (https)."
            : nil
        self.storageKey = Self.storageKey(issuerIdentifier: trimmedIssuer, clientId: clientId)

        let nilMarker = "\u{1}nil"
        let endpointParts = endpoints.map { e in
            [e.issuer, e.authorizationEndpoint, e.tokenEndpoint, e.jwksUri, e.userinfoEndpoint ?? nilMarker,
             e.revocationEndpoint ?? nilMarker, e.endSessionEndpoint ?? nilMarker,
             e.pushedAuthorizationRequestEndpoint ?? nilMarker,
             e.idTokenSigningAlgValuesSupported.joined(separator: ",")].joined(separator: "\u{1}")
        } ?? nilMarker
        // By value: two configurations built in two places with the same numbers are the same
        // configuration, and a RetryPolicy compared by identity would say otherwise.
        let retry = [
            "\(retryPolicy.maxAttemptsPerOrigin)", "\(retryPolicy.maxTotalAttempts)", "\(retryPolicy.initialBackoff)",
            "\(retryPolicy.backoffMultiplier)", "\(retryPolicy.maxBackoff)", "\(retryPolicy.totalBudget)",
        ].joined(separator: ",")
        self.fingerprint = [
            trimmedIssuer, endpointParts, clientId, redirectUri, postLogoutRedirectUri ?? nilMarker,
            self.effectiveScopes.sorted().joined(separator: " "), "\(tokenBinding)", "\(pushedAuthorization)",
            protectedOrigins.sorted().joined(separator: " "), endSessionEndpoint ?? nilMarker, retry,
            "\(unlockPolicy)", "\(clockSkewTolerance)",
        ].joined(separator: "\u{0}")
    }

    /// base64url(SHA-256("<issuer>\n<clientId>")), first 16 characters.
    static func storageKey(issuerIdentifier: String, clientId: String) -> String {
        let digest = SHA256.hash(data: Data("\(issuerIdentifier)\n\(clientId)".utf8))
        return String(Base64URLEncoder.encode(Data(digest)).prefix(storageKeyLength))
    }
}

/// What one `login()` adds to the configured defaults (`spec/oauth-sdk-api.md` section 6). The
/// SDK always sends `response_type=code`, PKCE `S256`, a fresh `state` and `nonce`; nothing here
/// can change that, and a key in `extraParameters` that collides with a parameter the SDK sets
/// is refused at construction.
public struct LoginOptions: Sendable {
    /// Replaces the configured scopes for this request; `openid` is still added.
    public let scopes: Set<String>?
    public let prompt: AuthorizationParameters.Prompt?
    public let loginHint: String?
    public let uiLocales: [String]
    public let acrValues: [String]
    /// Seconds; when set, the ID token must carry `auth_time` and it is checked.
    public let maxAge: Int?
    /// RFC 8707 `resource`, repeated; also sent on the token request.
    public let resources: [String]
    /// A provider's own parameters (`audience`, `claims`, `kc_idp_hint`), sent verbatim.
    public let extraParameters: [String: String]
    /// `prefersEphemeralWebBrowserSession`. Off by default: it breaks passkeys and single sign-on.
    public let ephemeralBrowser: Bool
    /// What the authorization request carries beyond scopes, `acr_values` and `max_age`.
    public let parameters: AuthorizationParameters

    public init(
        scopes: Set<String>? = nil, prompt: AuthorizationParameters.Prompt? = nil, loginHint: String? = nil,
        uiLocales: [String] = [], acrValues: [String] = [], maxAge: Int? = nil, resources: [String] = [],
        extraParameters: [String: String] = [:], ephemeralBrowser: Bool = false
    ) throws {
        for scope in scopes ?? [] where !URLRules.isScopeToken(scope) {
            throw URLRules.invalid("a scope is a single token without whitespace")
        }
        if let maxAge, maxAge < 0 { throw URLRules.invalid("maxAge must not be negative: \(maxAge)") }
        self.parameters = try AuthorizationParameters(
            prompt: prompt, loginHint: loginHint, uiLocales: uiLocales, resources: resources, extra: extraParameters
        )
        self.scopes = scopes
        self.prompt = prompt
        self.loginHint = loginHint
        self.uiLocales = uiLocales
        self.acrValues = acrValues
        self.maxAge = maxAge
        self.resources = resources
        self.extraParameters = extraParameters
        self.ephemeralBrowser = ephemeralBrowser
    }

    public static let `default` = try! LoginOptions()
}

/// What `logout()` does beyond the unconditional local wipe (`spec/oauth-sdk-api.md` section 12).
public struct LogoutOptions: Sendable, Equatable {
    /// End the provider's session through the browser when an `end_session_endpoint` is known.
    public let endSession: Bool
    /// Revoke the refresh token when a `revocation_endpoint` is advertised.
    public let revoke: Bool

    public init(endSession: Bool = true, revoke: Bool = true) {
        self.endSession = endSession
        self.revoke = revoke
    }

    public static let `default` = LogoutOptions()
}

// MARK: - Shared validation

enum RedirectKind: Equatable { case universalLink, loopback, customScheme }

/// URL rules shared by the configuration and the request scope. Swift's `URL` accepts almost
/// anything, so parsing goes through `URLComponents` and the pieces are checked by hand.
enum URLRules {
    /// The loopback names RFC 8252 section 7.3 allows, brackets stripped.
    static let loopbackHosts: Set<String> = ["127.0.0.1", "localhost", "::1"]

    static func invalid(_ detail: String) -> OAuthError {
        .configuration(.invalidConfiguration(detail: detail))
    }

    /// Lower-cased, IPv6 brackets stripped, so `[::1]` and `::1` compare equal whichever way
    /// Foundation reports them.
    static func normalizedHost(_ host: String?) -> String? {
        guard var host = host?.lowercased(), !host.isEmpty else { return nil }
        if host.hasPrefix("[") && host.hasSuffix("]") { host = String(host.dropFirst().dropLast()) }
        return host.isEmpty ? nil : host
    }

    static func isLoopback(_ host: String?) -> Bool {
        normalizedHost(host).map(loopbackHosts.contains) ?? false
    }

    static func isScopeToken(_ scope: String) -> Bool {
        !scope.isEmpty && !scope.unicodeScalars.contains { $0.properties.isWhitespace }
    }

    /// An absolute `https` URL with a host, or `http` to a loopback host.
    @discardableResult
    static func requireHttps(_ name: String, _ url: String) throws -> URLComponents {
        guard let components = URLComponents(string: url), let scheme = components.scheme?.lowercased(),
              let host = normalizedHost(components.host)
        else { throw invalid("\(name) must be an absolute https URL (http only on loopback): \(url)") }
        if !(scheme == "https" || (scheme == "http" && isLoopback(host))) {
            throw invalid("\(name) must be an absolute https URL (http only on loopback): \(url)")
        }
        return components
    }

    static func requireIssuer(_ issuer: String) throws {
        let components: URLComponents
        do { components = try requireHttps("issuer", issuer) } catch {
            throw invalid("issuer must be an https URL with a host (http only on loopback): \(issuer)")
        }
        // RFC 8414 section 2: the well-known path is appended to the issuer verbatim.
        if !(components.query ?? "").isEmpty || !(components.fragment ?? "").isEmpty {
            throw invalid("issuer must not carry a query or fragment: \(issuer)")
        }
    }

    /// `scheme://host[:port]` with nothing after it but an optional `/`; returns the normalised origin.
    static func parseOrigin(_ origin: String, name: String) throws -> String {
        let components = try requireHttps(name, origin)
        if !(components.path.isEmpty || components.path == "/") || components.query != nil
            || components.fragment != nil || components.user != nil || components.password != nil {
            throw invalid("a protected origin is scheme://host[:port] with no path, query or fragment: \(origin)")
        }
        // requireHttps proved scheme and host are present.
        return originString(scheme: components.scheme ?? "", host: components.host, port: components.port)
    }

    /// `scheme://host:port` with the default port written out and the host lower-cased: the
    /// form the origin comparison and the per-origin DPoP nonce cache both use.
    static func originString(scheme: String, host: String?, port: Int?) -> String {
        let scheme = scheme.lowercased()
        let effective = port ?? (scheme == "https" ? 443 : 80)
        return "\(scheme)://\(normalizedHost(host) ?? ""):\(effective)"
    }

    static func parseRedirect(_ raw: String, name: String) throws -> (url: URL, kind: RedirectKind) {
        guard let components = URLComponents(string: raw), let scheme = components.scheme?.lowercased(), !scheme.isEmpty,
              let url = URL(string: raw)
        else { throw invalid("\(name) must be an absolute URI: \(raw)") }
        if components.fragment != nil { throw invalid("\(name) must not carry a fragment: \(raw)") }
        let host = normalizedHost(components.host)
        switch scheme {
        case "https":
            // An opaque "https:callback" has no host and cannot be a universal link.
            if host == nil { throw invalid("\(name) must have a host: \(raw)") }
            return (url, .universalLink)
        case "http":
            // Cleartext to a host the app does not control is refused; loopback is RFC 8252 7.3.
            if isLoopback(host) { return (url, .loopback) }
            throw invalid("\(name) must not be cleartext http: \(raw)")
        default:
            return (url, .customScheme)
        }
    }
}

/// base64url without padding (RFC 4648 section 5), as JOSE and the storage key use it.
enum Base64URLEncoder {
    static func encode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
