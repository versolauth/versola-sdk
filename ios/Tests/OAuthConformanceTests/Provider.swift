import Foundation

/// The staged OpenID Provider (`conformance/providers/<name>/docker-compose.yml`) and the user
/// the driver signs in as, from the environment. With no issuer set every scenario is skipped,
/// so `swift test` and the simulator run stay unit runs. The twin of the Android driver's
/// `Provider`; what differs per provider is the same `Profile`.
struct Provider: Sendable {
    /// The provider's issuer as it is reached directly: where the proxy forwards to.
    let issuer: String
    let profile: Profile
    let username: String
    let password: String

    var name: String { profile.key }
    var login: ProviderLogin { profile.login }

    /// `scheme://host[:port]` of the issuer.
    var origin: String {
        let afterScheme = issuer.components(separatedBy: "://").dropFirst().joined(separator: "://")
        return issuer.components(separatedBy: "://").first! + "://" + (afterScheme.split(separator: "/", maxSplits: 1).first.map(String.init) ?? "")
    }

    /// The issuer's path (`/realms/conformance` on Keycloak, nothing on Hydra), re-rooted at the proxy's origin.
    var issuerPath: String { profile.issuerAtRoot ? "" : String(issuer.dropFirst(origin.count)) }

    var scopes: Set<String> { profile.scopes }
    var noRefreshScopes: Set<String> { profile.noRefreshScopes }

    enum Profile: String, Sendable, CaseIterable {
        case keycloak, hydra

        var key: String { rawValue }
        var login: ProviderLogin { self == .keycloak ? KeycloakLogin() : HydraLogin() }
        var issuerAtRoot: Bool { self == .hydra }
        var scopes: Set<String> { self == .hydra ? ["openid", "profile", "offline_access"] : ["openid", "profile"] }
        var noRefreshScopes: Set<String> { ["openid", "profile"] }
        var defaultUsername: String { self == .hydra ? "foo@bar.com" : "alice" }
        var defaultPassword: String { self == .hydra ? "foobar" : "alice-password" }
    }

    /// The public client: authorization code + PKCE, refresh tokens for `scopes`.
    static let clientId = "conformance-app"
    /// The same client without refresh tokens and with ten-second access tokens (scenario 31).
    static let noRefreshClientId = "conformance-app-norefresh"
    /// The same client again, but the provider refuses a token that is not bound to a DPoP key
    /// (scenario 33). Keycloak only: Hydra does not advertise DPoP (`spec/providers.md`).
    static let dpopClientId = "conformance-app-dpop"
    static let redirectUri = "https://conformance.example.com/oauth"
    static let postLogoutRedirectUri = "https://conformance.example.com/signed-out"

    /// Where the SDK is configured to find the provider: a virtual origin the in-process proxy
    /// answers for. Hydra's `hydra.yml` names this exact value as `urls.self`.
    static let proxyOrigin = "http://localhost:14444"

    /// - Throws: `ConformanceFailure` for a provider name without a profile, so the test fails
    ///   readably instead of the process ending.
    static func fromEnvironment() throws -> Provider? {
        let env = ProcessInfo.processInfo.environment
        guard let raw = env["OAUTH_CONFORMANCE_ISSUER"]?.trimmingCharacters(in: .whitespaces), !raw.isEmpty else { return nil }
        let issuer = raw.hasSuffix("/") ? String(raw.dropLast()) : raw
        let name = env["OAUTH_CONFORMANCE_PROVIDER"].flatMap { $0.isEmpty ? nil : $0 } ?? "keycloak"
        guard let profile = Profile(rawValue: name) else { throw ConformanceFailure("no profile for provider '\(name)' (conformance/README.md, Providers)") }
        return Provider(
            issuer: issuer,
            profile: profile,
            username: env["OAUTH_CONFORMANCE_USERNAME"].flatMap { $0.isEmpty ? nil : $0 } ?? profile.defaultUsername,
            password: env["OAUTH_CONFORMANCE_PASSWORD"].flatMap { $0.isEmpty ? nil : $0 } ?? profile.defaultPassword
        )
    }
}

/// The provider-specific half of the browser leg: given a page the conversation landed on, act
/// on it as the test user would and return the form post to send; nil for a page with nothing
/// to act on, where a browser would stay (the user "closes the tab").
protocol ProviderLogin: Sendable {
    func step(page: String, pageURL: URL, username: String, password: String) -> FormPost?
}

struct FormPost: Sendable {
    let url: URL
    let fields: [(String, String)]
}

enum HTMLForms {
    /// The `action` of the first form matching `marker`, HTML-unescaped and resolved against the page.
    static func action(in page: String, marker: String, pageURL: URL) -> URL? {
        guard let form = page.range(of: marker, options: .regularExpression) else { return nil }
        let tag = String(page[form])
        guard let action = tag.range(of: #"action="([^"]*)""#, options: .regularExpression) else { return nil }
        let value = String(tag[action]).dropFirst(8).dropLast().replacingOccurrences(of: "&amp;", with: "&")
        return URL(string: String(value), relativeTo: pageURL)?.absoluteURL
    }

    static func attribute(_ pattern: String, in page: String) -> String? {
        guard let regex = try? NSRegularExpression(pattern: pattern), let match = regex.firstMatch(in: page, range: NSRange(page.startIndex..., in: page)),
              let range = Range(match.range(at: 1), in: page) else { return nil }
        return String(page[range])
    }
}

/// Keycloak 26: the realm's login page, whose `kc-form-login` form posts `username`, `password`
/// and an empty `credentialId`; a correct password answers 302 to the client's redirect URI.
struct KeycloakLogin: ProviderLogin {
    func step(page: String, pageURL: URL, username: String, password: String) -> FormPost? {
        guard let action = HTMLForms.action(in: page, marker: #"<form[^>]*id="kc-form-login"[^>]*>"#, pageURL: pageURL) else { return nil }
        return FormPost(url: action, fields: [("username", username), ("password", password), ("credentialId", "")])
    }
}

/// Ory Hydra with Ory's reference login-consent app: login, consent and logout forms, each with
/// a `_csrf` token (paired with the app's `_csrf` cookie) and the `challenge`.
struct HydraLogin: ProviderLogin {
    func step(page: String, pageURL: URL, username: String, password: String) -> FormPost? {
        guard let action = HTMLForms.action(in: page, marker: #"<form[^>]*>"#, pageURL: pageURL),
              let csrf = HTMLForms.attribute(#"name="_csrf"\s+value="([^"]*)""#, in: page),
              let challenge = HTMLForms.attribute(#"name="challenge"\s+value="([^"]*)""#, in: page) else { return nil }
        let common = [("_csrf", csrf), ("challenge", challenge)]
        if page.contains("name=\"email\"") {
            return FormPost(url: action, fields: common + [("email", username), ("password", password), ("submit", "Log in")])
        }
        if page.contains("name=\"grant_scope\"") {
            // Attribute order is the template's, not ours: the tag first, then its value.
            let tags = try! NSRegularExpression(pattern: #"<input[^>]*name="grant_scope"[^>]*>"#)
            let scopes = tags.matches(in: page, range: NSRange(page.startIndex..., in: page)).compactMap { match -> String? in
                guard let range = Range(match.range, in: page) else { return nil }
                return HTMLForms.attribute(#"value="([^"]*)""#, in: String(page[range]))
            }
            return FormPost(url: action, fields: common + scopes.map { ("grant_scope", $0) } + [("submit", "Allow access")])
        }
        if pageURL.path.contains("/logout") {
            return FormPost(url: action, fields: common + [("submit", "Yes")])
        }
        return nil
    }
}
