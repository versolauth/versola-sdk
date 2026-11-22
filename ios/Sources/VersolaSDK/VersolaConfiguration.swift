import CryptoKit
import Foundation
import OAuthClient
import OAuthCore

/// What the ``Versola`` facade is configured with (`spec/versola-sdk-api.md` section 3): the edge
/// the app signs in and calls APIs through, and the client it is registered as. Validated here, so
/// a bad value is `OAuthError.configuration(.invalidConfiguration)` at construction and never
/// behind a login screen.
///
/// There is nothing to choose about the protocol: an edge-fronted native client is always
/// DPoP-bound, always pushes its request and always redirects to an `https` link, so none of those
/// is a parameter.
public struct VersolaConfiguration: Sendable {
    /// The public origin of the edge, as its own configuration names it (`edge-url`): `https`, or
    /// `http` on `localhost`, `127.0.0.1` or `[::1]` for an edge on the developer's machine. An
    /// origin and nothing more: edge computes what every DPoP proof must name from its own origin
    /// and the request's path, so a path, query or fragment here could only produce proofs it
    /// refuses.
    public let edgeUrl: String
    /// The client id the app is registered under at the deployment.
    public let clientId: String
    /// Where the browser returns to: an `https` Universal Link of the app, which the app hands to
    /// ``Versola/handleRedirect(_:)`` when the system delivers it. A private-use scheme or a loopback
    /// address is refused, as the server refuses to register one for a client fronted by edge.
    public let redirectUri: String
    /// The issuer of the deployment, compared as written with the `iss` of the redirect (RFC 9207)
    /// and of the ID token. Defaults to ``edgeUrl``, which is what it is for a deployment's own
    /// edge. Set it when the issuer is another address: always for a partner's edge (the issuer is
    /// the operator's), and when the deployment writes its issuer differently, a trailing slash
    /// included. A wrong value fails the first sign-in with `configuration(.issuerMismatch)`, before
    /// any token request.
    public let issuer: String
    /// Where the browser returns to after `logout()` ended the server session; an `https` Universal
    /// Link like ``redirectUri``, registered among the tenant's post-logout redirect URIs. Without it
    /// the signed-out page stays open until the user dismisses it and `logout()` reports
    /// `sessionEnded = false`; the local sign-out completes either way.
    public let postLogoutRedirectUri: String?
    /// Refuse to sign in with a DPoP key that did not land in the Secure Enclave
    /// (`configuration(.hardwareBindingUnavailable)`, before any request). Off, a software key is
    /// used and reported by ``Versola/keyAttestation()``; the app decides whether it accepts one.
    public let requireHardwareKey: Bool
    /// Whether the stored credentials are readable only while the device is unlocked.
    public let unlockPolicy: UnlockPolicy
    /// How the SDK repeats its own requests after a transient failure; the default suits most apps.
    public let retryPolicy: RetryPolicy
    /// How far the device clock may be from the server's when the ID token's times are judged, in
    /// seconds; at most five minutes.
    public let clockSkewTolerance: TimeInterval
    /// Where the SDK's warnings go; by default the unified log.
    public let logger: any OAuthLogger
    /// The session the SDK's own requests and the authenticated session are built on, so that its
    /// timeouts, pinning and proxy are the app's. Redirects are never followed on the SDK's own
    /// requests whatever the session does.
    public let urlSession: URLSession

    /// The edge's origin without a trailing slash: what native URLs and the request scope are built on.
    package let edgeOrigin: String
    /// What the protocol core is configured with. Its issuer drops a trailing slash; the checks that
    /// compare `iss` use ``issuer`` itself (`EdgeMetadata`, `TlsTrustedIdTokenValidator`).
    package let core: CoreConfiguration
    /// Names this client's storage, its Keychain items and its key: a hash, so that neither a file
    /// name nor a Keychain account carries an address, and two clients in one process (two edges, two
    /// client ids) or the two facades never share a store.
    package let storageKey: String
    /// Everything a second `create` for the same storage must agree on, by value.
    package let fingerprint: String

    static let storageKeyLength = 16

    /// - Throws: `OAuthError.configuration(.invalidConfiguration)` naming the first offending field.
    public init(
        edgeUrl: String,
        clientId: String,
        redirectUri: String,
        issuer: String? = nil,
        postLogoutRedirectUri: String? = nil,
        requireHardwareKey: Bool = false,
        unlockPolicy: UnlockPolicy = .none,
        retryPolicy: RetryPolicy = .default,
        clockSkewTolerance: TimeInterval = 60,
        logger: any OAuthLogger = OSLogLogger(),
        urlSession: URLSession = .shared
    ) throws {
        let edge: URLComponents
        do { edge = try URLRules.requireHttps("edgeUrl", edgeUrl) } catch {
            throw URLRules.invalid("edgeUrl must be an absolute https URL (http only on a loopback host: localhost, 127.0.0.1, [::1])")
        }
        if !(edge.path.isEmpty || edge.path == "/") || edge.query != nil || edge.fragment != nil
            || edge.user != nil || edge.password != nil {
            throw URLRules.invalid("edgeUrl must be an origin: no path, query, fragment or credentials")
        }
        if !(0...300).contains(clockSkewTolerance) {
            throw URLRules.invalid("clockSkewTolerance must be between 0 and 300 seconds: \(clockSkewTolerance)")
        }
        if clientId.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            throw URLRules.invalid("clientId must not be blank")
        }
        let effectiveIssuer = issuer ?? edgeUrl
        try URLRules.requireIssuer(effectiveIssuer)
        // An edge-fronted native client redirects to an https link only, in every tenant.
        let redirect = try URLRules.parseRedirect(redirectUri, name: "redirectUri")
        if redirect.kind != .universalLink {
            throw URLRules.invalid("redirectUri must be an https Universal Link: a client fronted by edge has no other kind")
        }
        let postLogout = try postLogoutRedirectUri.map { try URLRules.parseRedirect($0, name: "postLogoutRedirectUri") }
        if let postLogout, postLogout.kind != .universalLink {
            throw URLRules.invalid("postLogoutRedirectUri must be an https Universal Link")
        }

        var origin = edgeUrl
        while origin.hasSuffix("/") { origin.removeLast() }

        self.edgeUrl = edgeUrl
        self.clientId = clientId
        self.redirectUri = redirectUri
        self.issuer = effectiveIssuer
        self.postLogoutRedirectUri = postLogoutRedirectUri
        self.requireHardwareKey = requireHardwareKey
        self.unlockPolicy = unlockPolicy
        self.retryPolicy = retryPolicy
        self.clockSkewTolerance = clockSkewTolerance
        self.logger = logger
        self.urlSession = urlSession
        self.edgeOrigin = origin
        self.core = CoreConfiguration(issuer: effectiveIssuer, clientId: clientId, redirectUri: redirect.url, postLogoutRedirectUri: postLogout?.url)

        let digest = SHA256.hash(data: Data("\(origin)\n\(effectiveIssuer)\n\(clientId)".utf8))
        self.storageKey = String(Base64URLEncoder.encode(Data(digest)).prefix(Self.storageKeyLength))

        let nilMarker = "\u{1}nil"
        // By value: two configurations built in two places with the same numbers are the same configuration.
        let retry = [
            "\(retryPolicy.maxAttemptsPerOrigin)", "\(retryPolicy.maxTotalAttempts)", "\(retryPolicy.initialBackoff)",
            "\(retryPolicy.backoffMultiplier)", "\(retryPolicy.maxBackoff)", "\(retryPolicy.totalBudget)",
        ].joined(separator: ",")
        self.fingerprint = [
            origin, effectiveIssuer, clientId, redirectUri, postLogoutRedirectUri ?? nilMarker,
            "\(requireHardwareKey)", "\(unlockPolicy)", retry, "\(clockSkewTolerance)",
        ].joined(separator: "\u{0}")
    }

    /// Whether `other` wires the same `URLSession` and the same logger: by identity for a class, and
    /// by type for a logger that is a value (two default `OSLogLogger`s are the same).
    func sharesWiring(with other: VersolaConfiguration) -> Bool {
        func identity(_ logger: any OAuthLogger) -> AnyHashable {
            let object = logger as AnyObject
            return type(of: logger) is AnyClass ? AnyHashable(ObjectIdentifier(object)) : AnyHashable(String(describing: type(of: logger)))
        }
        return urlSession === other.urlSession && identity(logger) == identity(other.logger)
    }
}
