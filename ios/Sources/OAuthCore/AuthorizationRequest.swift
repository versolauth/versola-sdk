import Foundation

/// `application/x-www-form-urlencoded` and query-string encoding, shared by the authorization
/// URI, a pushed request's body and the end-session URI so all three encode alike.
///
/// Everything outside the RFC 3986 unreserved set is percent-encoded, a space as `%20`. Form
/// encoding proper would send `+`, which is legal but not understood by every server's parser,
/// and `scope`, `acr_values` and `ui_locales` are space-delimited, so the difference shows.
public enum FormEncoding {
    /// `name=value` pairs joined with `&`, each side percent-encoded, in the order given.
    public static func encode(_ pairs: [(String, String)]) -> String {
        pairs.map { "\(percentEncode($0.0))=\(percentEncode($0.1))" }.joined(separator: "&")
    }

    /// The encoded pairs as a request body.
    public static func body(_ pairs: [(String, String)]) -> Data {
        Data(encode(pairs).utf8)
    }

    /// `endpoint` with `pairs` as its query, appended with `&` when it already has one (a
    /// provider whose authorization endpoint carries a tenant parameter, say).
    public static func withQuery(_ endpoint: String, _ pairs: [(String, String)]) throws -> URL {
        let separator = endpoint.contains("?") ? "&" : "?"
        let text = pairs.isEmpty ? endpoint : endpoint + separator + encode(pairs)
        guard let url = URL(string: text), url.scheme != nil else {
            throw OAuthError.configuration(.invalidConfiguration(detail: "not a URL: \(endpoint)"))
        }
        return url
    }

    static func percentEncode(_ value: String) -> String {
        var out = ""
        out.reserveCapacity(value.utf8.count)
        for byte in value.utf8 {
            switch byte {
            case UInt8(ascii: "A")...UInt8(ascii: "Z"), UInt8(ascii: "a")...UInt8(ascii: "z"),
                 UInt8(ascii: "0")...UInt8(ascii: "9"), UInt8(ascii: "-"), UInt8(ascii: "."),
                 UInt8(ascii: "_"), UInt8(ascii: "~"):
                out.unicodeScalars.append(Unicode.Scalar(byte))
            default:
                out += String(format: "%%%02X", byte)
            }
        }
        return out
    }
}

/// An authorization request, built once and then split in two: the URI the browser opens, and
/// the `PendingAuthorizationRequest` persisted before it opens.
///
/// PKCE, `state` and `nonce` are not parameters: they are generated here, always. There is no
/// way for an integrator to supply, disable or weaken them.
public struct AuthorizationRequest: Sendable {
    public let configuration: CoreConfiguration
    /// In the order given, without duplicates: the order is what the provider's consent page
    /// shows, and a `Set` would make the wire format vary from run to run.
    public let scopes: [String]
    public let state: String
    public let nonce: String
    public let codeVerifier: CodeVerifier
    public let acrValues: [String]
    public let maxAge: Int?
    /// RFC 9449 section 10: commits the code to the DPoP key before it exists, so a stolen code
    /// cannot be redeemed against another key. Nil whenever the session is not key-bound.
    public let dpopJkt: String?
    /// What `login()` added beyond scopes, `acr_values` and `max_age`; sent after `dpop_jkt`.
    public let parameters: AuthorizationParameters

    init(
        configuration: CoreConfiguration, scopes: [String], state: String, nonce: String,
        codeVerifier: CodeVerifier, acrValues: [String], maxAge: Int?, dpopJkt: String?,
        parameters: AuthorizationParameters
    ) {
        self.configuration = configuration
        self.scopes = scopes
        self.state = state
        self.nonce = nonce
        self.codeVerifier = codeVerifier
        self.acrValues = acrValues
        self.maxAge = maxAge
        self.dpopJkt = dpopJkt
        self.parameters = parameters
    }

    /// Generates `state`, `nonce` and the verifier from `random` (the platform CSPRNG in
    /// production, 256 bits each).
    public static func create(
        configuration: CoreConfiguration,
        scopes: [String],
        acrValues: [String] = [],
        maxAge: Int? = nil,
        dpopJkt: String? = nil,
        parameters: AuthorizationParameters = .none,
        random: RandomSource = SystemRandomSource()
    ) -> AuthorizationRequest {
        var seen = Set<String>()
        return AuthorizationRequest(
            configuration: configuration,
            scopes: scopes.filter { seen.insert($0).inserted },
            state: SecureTokens.generate(random),
            nonce: SecureTokens.generate(random),
            codeVerifier: CodeVerifier.generate(random),
            acrValues: acrValues,
            maxAge: maxAge,
            dpopJkt: dpopJkt,
            parameters: parameters
        )
    }

    /// Every parameter, in wire order, as (name, value) pairs. The one list both `toUri` (the
    /// query) and a pushed request (the form body, RFC 9126 section 2.1) are built from, so
    /// the two cannot drift. `resource` repeats once per value (RFC 8707 section 2.1) and
    /// `ui_locales` is one space-delimited value (OpenID Connect Core section 3.1.2.1). A
    /// public client has no credential, so there is nothing here to authenticate with.
    public func formParameters() -> [(String, String)] {
        var pairs: [(String, String)] = [
            ("response_type", "code"),
            ("client_id", configuration.clientId),
            ("redirect_uri", configuration.redirectUri.absoluteString),
        ]
        if !scopes.isEmpty { pairs.append(("scope", scopes.joined(separator: " "))) }
        pairs.append(("state", state))
        pairs.append(("nonce", nonce))
        pairs.append(("code_challenge", codeVerifier.challengeS256()))
        pairs.append(("code_challenge_method", "S256"))
        if !acrValues.isEmpty { pairs.append(("acr_values", acrValues.joined(separator: " "))) }
        if let maxAge { pairs.append(("max_age", String(maxAge))) }
        if let dpopJkt { pairs.append(("dpop_jkt", dpopJkt)) }
        if let prompt = parameters.prompt { pairs.append(("prompt", prompt.rawValue)) }
        if let hint = parameters.loginHint { pairs.append(("login_hint", hint)) }
        if !parameters.uiLocales.isEmpty {
            pairs.append(("ui_locales", parameters.uiLocales.joined(separator: " ")))
        }
        for resource in parameters.resources { pairs.append(("resource", resource)) }
        // A dictionary has no order; sorting keeps the wire format reproducible.
        for (name, value) in parameters.extra.sorted(by: { $0.key < $1.key }) {
            pairs.append((name, value))
        }
        return pairs
    }

    /// The authorization URI: the endpoint with every `formParameters` pair as its query.
    public func toUri(authorizationEndpoint: String) throws -> URL {
        try FormEncoding.withQuery(authorizationEndpoint, formParameters())
    }

    /// What is persisted before the browser opens.
    public func toPending(createdAt: Date, issRequired: Bool) -> PendingAuthorizationRequest {
        PendingAuthorizationRequest(
            state: state,
            nonce: nonce,
            codeVerifier: codeVerifier.value,
            scopes: scopes,
            redirectUri: configuration.redirectUri.absoluteString,
            acrValues: acrValues,
            maxAge: maxAge,
            createdAt: createdAt,
            // Kept so the exchange can repeat them (RFC 8707 section 2.2); nothing else of the
            // parameters is needed once the browser has them.
            resources: parameters.resources,
            issRequired: issRequired
        )
    }
}
