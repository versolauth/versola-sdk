import Foundation
import OAuthCore

/// What one ``Versola/login(_:)`` asks for (`spec/versola-sdk-api.md` section 5). Each option is
/// one of the authorization parameters edge forwards from `/native/start`, and there is no other:
/// edge drops a parameter it does not forward without an error, so a free-form map here would let
/// an app set something that silently does nothing.
///
/// The SDK always sends the redirect URI and a fresh `nonce`; PKCE, `state` and the binding to the
/// device key are edge's and cannot be supplied. A value that cannot be sent (a scope with a space
/// in it, a negative `maxAge`) is refused by the call that receives the options, with
/// `OAuthError.configuration(.invalidConfiguration)`.
public struct LoginOptions: Sendable, Equatable {
    /// Added to `openid` and `offline_access`, which every sign-in asks for: the facade is a session.
    public var scopes: Set<String>
    /// The authentication contexts to ask for; ``Acr/sensitive`` is the built-in one. A step-up takes
    /// them from the challenge, not from here.
    public var acrValues: [String]
    /// Seconds since the user last authenticated; when set, the ID token's `auth_time` is checked
    /// against it. A step-up takes it from the challenge.
    public var maxAge: Int?
    /// Whether the sign-in page may interact; `.none` makes an interaction error
    /// `reauthenticate(.interactionRequired)`.
    public var prompt: AuthorizationParameters.Prompt?
    /// Prefills the identifier on the sign-in page.
    public var loginHint: String?
    /// `ui_locales`, in order of preference.
    public var uiLocales: [String]
    /// RFC 8707 `resource`, one per value; sent at `/native/start` only.
    public var resources: [String]
    /// OpenID Connect Core 5.5 `claims`: a JSON object as text, sent as given.
    public var claims: String?
    /// RFC 9396 `authorization_details`: a JSON array as text, sent as given.
    public var authorizationDetails: String?
    /// `prefersEphemeralWebBrowserSession`: open the browser without the user's shared browsing state.
    /// Off by default: it breaks passkeys and single sign-on.
    public var ephemeralBrowser: Bool

    public init(
        scopes: Set<String> = [], acrValues: [String] = [], maxAge: Int? = nil,
        prompt: AuthorizationParameters.Prompt? = nil, loginHint: String? = nil, uiLocales: [String] = [],
        resources: [String] = [], claims: String? = nil, authorizationDetails: String? = nil,
        ephemeralBrowser: Bool = false
    ) {
        self.scopes = scopes
        self.acrValues = acrValues
        self.maxAge = maxAge
        self.prompt = prompt
        self.loginHint = loginHint
        self.uiLocales = uiLocales
        self.resources = resources
        self.claims = claims
        self.authorizationDetails = authorizationDetails
        self.ephemeralBrowser = ephemeralBrowser
    }

    /// The scopes as they are sent: the options' own with `openid` present, sorted so that the wire
    /// format does not vary from run to run and two equal calls compare equal. `offline_access` is
    /// added by the session (`RefreshTokenPolicy.required`).
    func requestedScopes() throws -> [String] {
        for scope in scopes where scope.isEmpty || scope.unicodeScalars.contains(where: { $0.properties.isWhitespace }) {
            throw OAuthError.configuration(.invalidConfiguration(detail: "a scope is a single token without whitespace"))
        }
        return Array(scopes.union(["openid"])).sorted()
    }

    /// What the core builds the request from. The two parameters the core has no field for travel in
    /// its `extra` map under their wire names; the edge starter forwards exactly those two and nothing
    /// else of the map.
    func authorizationParameters(maxAge: Int?) throws -> AuthorizationParameters {
        if let maxAge, maxAge < 0 {
            throw OAuthError.configuration(.invalidConfiguration(detail: "maxAge must not be negative: \(maxAge)"))
        }
        var extra: [String: String] = [:]
        if let claims { extra["claims"] = claims }
        if let authorizationDetails { extra["authorization_details"] = authorizationDetails }
        return try AuthorizationParameters(
            prompt: prompt, loginHint: loginHint, uiLocales: uiLocales, resources: resources, extra: extra
        )
    }
}

/// Authentication context class references a Versola deployment has built in.
public enum Acr {
    /// The strongest factor the user has that the client's sign-in flow can ask for (a passkey, else
    /// a password, else a one-time code). What an endpoint that guards something sensitive asks for;
    /// pair it with a maximum age, since it says how and not how recently.
    public static let sensitive = "sensitive"
}
