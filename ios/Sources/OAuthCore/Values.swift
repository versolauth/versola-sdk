import Foundation

// The value types on the facade's surface. Every one is `Sendable`, and every one that could
// carry a secret redacts it in `description` (`security.md`).

/// A short-lived access token, the one credential an app may hold directly (the escape hatch).
public struct AccessToken: Sendable, Equatable, CustomStringConvertible {
    public let value: String
    /// RFC 9449 §5: `DPoP` or `Bearer`, read off the token response's `token_type`.
    public let tokenType: String
    public init(value: String, tokenType: String) {
        self.value = value
        self.tokenType = tokenType
    }
    public var description: String { "AccessToken(\(tokenType), redacted)" }
}

/// Bearer by default; DPoP when the resource servers verify it (`spec/oauth-sdk-api.md` section 9).
public enum TokenBinding: Sendable, Equatable {
    case bearer
    /// `required`: `providerUnsupported("dpop")` when the provider does not advertise it,
    /// instead of a warning and a bearer session.
    case dpop(required: Bool = false)
}

/// RFC 9126 policy (`spec/oauth-sdk-api.md` section 7).
public enum PushedAuthorization: Sendable, Equatable {
    case never, whenAdvertised, required
}

/// Whether a token response without a `refresh_token` is accepted (the generic facade) or
/// refused (the Versola facade, which has nothing to hold without one).
public enum RefreshTokenPolicy: Sendable, Equatable {
    case required, optional
}

/// `spec/state-machine.md`'s `locked` state is reachable only under `onAppUnlock`.
public enum UnlockPolicy: Sendable, Equatable {
    case none
    /// The credentials unlock with the device (`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`).
    case onAppUnlock
}

/// What `logout()` did beyond the unconditional local wipe (`spec/oauth-sdk-api.md` section 12).
public struct LogoutOutcome: Sendable, Equatable {
    /// The provider acknowledged RP-initiated logout: the browser came back with the `state` sent.
    public let sessionEnded: Bool
    /// The provider took the refresh token's revocation. False when none is advertised or it failed.
    public let tokenRevoked: Bool
    public init(sessionEnded: Bool, tokenRevoked: Bool) {
        self.sessionEnded = sessionEnded
        self.tokenRevoked = tokenRevoked
    }
}

/// The claims of a validated ID token (`spec/oauth-sdk-api.md` section 11). Memory only; the
/// raw token and the `nonce` are not exposed, and `description` redacts the subject.
public struct IdTokenClaims: Sendable, Equatable, CustomStringConvertible {
    public let subject: String
    public let issuer: String
    public let audience: [String]
    public let issuedAt: Date
    public let expiresAt: Date
    public let authTime: Date?
    public let acr: String?
    public let amr: [String]
    /// `azp`, when the token carries one.
    public let authorizedParty: String?
    /// Every claim but `nonce` (spent by validation), the typed ones included, as text: strings
    /// verbatim, anything else as compact JSON. The same map Android's `all` holds.
    public let all: [String: String]

    public init(
        subject: String, issuer: String, audience: [String], issuedAt: Date, expiresAt: Date,
        authTime: Date? = nil, acr: String? = nil, amr: [String] = [], authorizedParty: String? = nil, all: [String: String] = [:]
    ) {
        self.subject = subject
        self.issuer = issuer
        self.audience = audience
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
        self.authTime = authTime
        self.acr = acr
        self.amr = amr
        self.authorizedParty = authorizedParty
        self.all = all
    }

    public var description: String { "IdTokenClaims(issuer: \(issuer), subject: redacted)" }
}

/// The UserInfo response (OpenID Connect Core 5.3). Profile data is personal data: redacted.
public struct UserInfo: Sendable, Equatable, CustomStringConvertible {
    public let subject: String
    public let claims: [String: String]
    public init(subject: String, claims: [String: String]) {
        self.subject = subject
        self.claims = claims
    }
    public var description: String { "UserInfo(redacted)" }
}

/// What one `login()` adds to the authorization request beyond scopes, `acr_values` and
/// `max_age` (`spec/oauth-sdk-api.md` section 6). A key in `extra` that collides with a
/// parameter the SDK sets is refused at construction.
public struct AuthorizationParameters: Sendable, Equatable {
    public enum Prompt: String, Sendable { case none, login, consent, selectAccount = "select_account", create }

    public var prompt: Prompt?
    public var loginHint: String?
    public var uiLocales: [String]
    /// RFC 8707 `resource`, repeated; also sent on the token request.
    public var resources: [String]
    /// A provider's own parameters, sent verbatim.
    public var extra: [String: String]

    public static let reserved: Set<String> = [
        "client_id", "redirect_uri", "response_type", "scope", "state", "nonce", "code_challenge",
        "code_challenge_method", "request_uri", "prompt", "max_age", "acr_values", "resource",
        "login_hint", "ui_locales", "dpop_jkt",
        // Not the SDK's to set, and not an app's either: a secret the type system keeps
        // unrepresentable, a JAR object that would replace the whole request, a response
        // mode that moves the response out of the query the validator reads.
        "client_secret", "request", "response_mode",
    ]

    public init(
        prompt: Prompt? = nil, loginHint: String? = nil, uiLocales: [String] = [],
        resources: [String] = [], extra: [String: String] = [:]
    ) throws {
        if let collision = extra.keys.first(where: { AuthorizationParameters.reserved.contains($0) }) {
            throw OAuthError.configuration(.invalidConfiguration(detail: "extra parameter '\(collision)' is set by the SDK"))
        }
        self.prompt = prompt
        self.loginHint = loginHint
        self.uiLocales = uiLocales
        self.resources = resources
        self.extra = extra
    }

    public static let none = try! AuthorizationParameters()
}
