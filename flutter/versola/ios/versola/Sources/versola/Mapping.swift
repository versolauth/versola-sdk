// Type conversion between the Pigeon messages and the SDK's public types. Nothing here decides
// anything: a value the SDK refuses is refused by the SDK, and the refusal is what crosses.
import Flutter
import Foundation
import VersolaSDK

extension VersolaConfigurationMessage {
    func toConfiguration() throws -> VersolaConfiguration {
        try VersolaConfiguration(
            edgeUrl: edgeUrl,
            clientId: clientId,
            redirectUri: redirectUri,
            // Nil is the SDK's own default (the edge URL): the glue does not restate it.
            issuer: issuer,
            postLogoutRedirectUri: postLogoutRedirectUri,
            requireHardwareKey: requireHardwareKey,
            unlockPolicy: unlockPolicy == .none ? .none : .onAppUnlock,
            retryPolicy: try retryPolicy.map {
                try RetryPolicy(
                    maxAttemptsPerOrigin: Int($0.maxAttemptsPerOrigin),
                    maxTotalAttempts: Int($0.maxTotalAttempts),
                    initialBackoff: TimeInterval($0.initialBackoffMillis) / 1000,
                    backoffMultiplier: $0.backoffMultiplier,
                    maxBackoff: TimeInterval($0.maxBackoffMillis) / 1000,
                    totalBudget: TimeInterval($0.totalBudgetMillis) / 1000
                )
            } ?? .default,
            clockSkewTolerance: TimeInterval(clockSkewToleranceSeconds),
            urlSession: NetworkSession.shared
        )
    }
}

/// The session the SDK's own requests (the native endpoints, and the app's through `httpClient()`)
/// go through. The SDK's default is `URLSession.shared`, whose disk cache would keep responses to
/// requests that carried a credential and whose cookie jar is shared with the rest of the app;
/// Android's client and `dart:io` have neither. This one keeps nothing: no cache, no cookies, no
/// credential storage, and no cached answer is ever used in place of a request.
enum NetworkSession {
    static let shared: URLSession = {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.urlCache = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.httpCookieAcceptPolicy = .never
        configuration.urlCredentialStorage = nil
        return URLSession(configuration: configuration)
    }()
}

extension VersolaLoginOptionsMessage {
    func toLoginOptions() -> LoginOptions {
        LoginOptions(
            scopes: Set(scopes),
            acrValues: acrValues,
            maxAge: maxAge.map(Int.init),
            prompt: prompt.map {
                switch $0 {
                case .none: return .none
                case .login: return .login
                case .consent: return .consent
                case .selectAccount: return .selectAccount
                case .create: return .create
                }
            },
            loginHint: loginHint,
            uiLocales: uiLocales,
            resources: resources,
            claims: claims,
            authorizationDetails: authorizationDetails,
            ephemeralBrowser: ephemeralBrowser
        )
    }
}

extension SessionState {
    func toMessage() -> VersolaSessionStateMessage {
        switch self {
        case .unauthenticated: return .unauthenticated
        case .authorizing: return .authorizing
        case .authenticated: return .authenticated
        case .refreshing: return .refreshing
        case .stepUpRequired: return .stepUpRequired
        case .locked: return .locked
        case .loggingOut: return .loggingOut
        }
    }
}

extension Error {
    /// What crosses for any error: an `OAuthError` as itself, anything else as a `Configuration`
    /// naming only its type. The error's text never leaves native code (`flutter.md`, "No secret
    /// in a `PlatformException` message").
    func toErrorMessage() -> VersolaErrorMessage {
        if let error = self as? OAuthError { return error.toMessage() }
        let name = String(describing: type(of: self))
        var m = VersolaErrorMessage(category: .configuration, kind: "invalidConfiguration", message: "configuration: unexpected \(name)")
        m.detail = "unexpected \(name)"
        m.sdkCode = "configuration.invalid_configuration"
        return m
    }
}

extension OAuthError {
    /// Flattens the taxonomy for the wire. `category` is the contract; `kind` is the case name
    /// in the spelling Dart's enums use, so the sealed hierarchy is rebuilt case for case. The
    /// text is the SDK's own description, which never carries a credential (`security.md`).
    func toMessage() -> VersolaErrorMessage {
        var m: VersolaErrorMessage
        switch self {
        case .recoverable(let cause):
            m = VersolaErrorMessage(category: .recoverable, kind: "", message: description)
            switch cause {
            case .userCancelled: m.kind = "userCancelled"
            case .systemCancelled: m.kind = "systemCancelled"
            case .pendingRequestExpired: m.kind = "pendingRequestExpired"
            case .network(let detail, let attempts, let elapsedMillis):
                m.kind = "network"; m.detail = detail; m.attempts = Int64(attempts); m.elapsedMillis = elapsedMillis
            case .server(let status, let retryAfterMillis, let attempts, let elapsedMillis):
                // An HTTP answer that kept the operation from finishing: the status says whether it
                // was a 429 or a 5xx, `retryAfterMillis` how long the server asked the app to wait.
                m.kind = "server"; m.status = Int64(status); m.retryAfterMillis = retryAfterMillis
                m.attempts = Int64(attempts); m.elapsedMillis = elapsedMillis
            case .unlockRequired: m.kind = "unlockRequired"
            case .nonceLoop(let origin): m.kind = "nonceLoop"; m.origin = origin
            case .accountMismatch: m.kind = "accountMismatch"
            }
        case .reauthenticate(let reason):
            m = VersolaErrorMessage(category: .reauthenticate, kind: "", message: description)
            switch reason {
            case .authorizationDenied: m.kind = "authorizationDenied"
            case .interactionRequired(let code): m.kind = "interactionRequired"; m.code = code
            case .credentialsInvalidated: m.kind = "credentialsInvalidated"
            case .grantRejected: m.kind = "grantRejected"
            case .sessionRejected: m.kind = "sessionRejected"
            case .sessionExpired: m.kind = "sessionExpired"
            }
        case .stepUp(let acrValues, let maxAge):
            m = VersolaErrorMessage(category: .stepUp, kind: "stepUp", message: description)
            m.acrValues = acrValues
            m.maxAge = maxAge.map(Int64.init)
        case .configuration(let detail):
            m = VersolaErrorMessage(category: .configuration, kind: "", message: description)
            switch detail {
            case .stateMismatch: m.kind = "stateMismatch"
            case .issuerMismatch(let expected, let received): m.kind = "issuerMismatch"; m.expected = expected; m.received = received
            case .malformedAuthorizationResponse: m.kind = "malformedAuthorizationResponse"
            case .authorizationRejected(let code, let description): m.kind = "authorizationRejected"; m.code = code; m.errorDescription = description
            case .tokenRequestRejected(let code, let description): m.kind = "tokenRequestRejected"; m.code = code; m.errorDescription = description
            case .tokenResponseMalformed(let detail): m.kind = "tokenResponseMalformed"; m.detail = detail
            case .discoveryFieldMissing(let field): m.kind = "discoveryFieldMissing"; m.field = field
            case .discoveryIssuerMismatch(let configured, let advertised): m.kind = "discoveryIssuerMismatch"; m.expected = configured; m.received = advertised
            case .discoveryMalformed(let detail): m.kind = "discoveryMalformed"; m.detail = detail
            case .invalidConfiguration(let detail): m.kind = "invalidConfiguration"; m.detail = detail
            case .noBrowserAvailable: m.kind = "noBrowserAvailable"
            case .idTokenRejected(let rejection): m.kind = "idTokenRejected"; m.idTokenRejection = rejection.rawValue
            case .userInfoRejected(let detail): m.kind = "userInfoRejected"; m.detail = detail
            case .providerUnsupported(let capability): m.kind = "providerUnsupported"; m.capability = capability
            case .hardwareBindingUnavailable(let detail): m.kind = "hardwareBindingUnavailable"; m.detail = detail
            // A facade's own detail (`edge_client_unknown` is the Versola facade's): Dart has no
            // name for it, so it is `unknown` with the name, never a guessed real case. The stable
            // code (`configuration.edge_client_unknown`) travels in `sdkCode`, set below. The
            // payload (the client id) is not sent: the name and the code say what happened.
            case .facade(let name, _): m.kind = "unknown"; m.detail = name
            }
        }
        // The stable `code` of `spec/errors.md`, distinct from `m.code`, the provider's OAuth error code.
        m.sdkCode = code
        return m
    }
}

// MARK: HTTP (`Versola.session()`)

extension VersolaHttpRequestMessage {
    /// The request Dart described, as a `URLRequest`, and nothing else: no header is added,
    /// removed or rewritten here (the SDK's session replaces `Authorization` and `DPoP` on the edge
    /// and leaves every other origin untouched). A repeated header name is folded by `URLRequest`
    /// itself, with a comma, which RFC 9110 section 5.3 makes equivalent. Whatever is not a valid
    /// HTTP request is `invalidConfiguration` with a fixed text: a header value can be a
    /// credential, so it is never quoted.
    func toURLRequest() throws -> URLRequest {
        func invalid() -> OAuthError {
            .configuration(.invalidConfiguration(detail: "the request is not a valid HTTP request (an absolute http(s) URL, a method, headers)"))
        }
        guard let parsed = URL(string: url), let scheme = parsed.scheme?.lowercased(), scheme == "http" || scheme == "https",
              let host = parsed.host, !host.isEmpty, !method.isEmpty else { throw invalid() }
        let payload = body.map { Data($0.data) }.flatMap { $0.isEmpty ? nil : $0 }
        // As OkHttp does: a body on GET or HEAD is refused, not dropped; URLSession would fail on it with an opaque error.
        if payload != nil, method == "GET" || method == "HEAD" { throw invalid() }
        var request = URLRequest(url: parsed)
        request.httpMethod = method
        // Nothing is read from or kept in a cache or a cookie jar: Android's OkHttp client and
        // `dart:io` have neither, and a cached GET would be answered with no request and no DPoP
        // proof. (What `URLSession` stores is the session's own configuration: see `NetworkSession`.)
        request.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        request.httpShouldHandleCookies = false
        for header in headers {
            guard Self.isToken(header.name), Self.isFieldValue(header.value) else { throw invalid() }
            request.addValue(header.value, forHTTPHeaderField: header.name)
        }
        request.httpBody = payload
        return request
    }

    /// Visible ASCII, space and tab, as OkHttp accepts on Android: a non-ASCII or control character
    /// (CR, LF, NUL, DEL included) is refused on both platforms rather than sent in whatever encoding.
    private static func isFieldValue(_ value: String) -> Bool {
        value.unicodeScalars.allSatisfy { $0 == "\t" || (0x20...0x7E).contains($0.value) }
    }

    /// RFC 9110 section 5.6.2 `token`.
    private static func isToken(_ name: String) -> Bool {
        !name.isEmpty && name.unicodeScalars.allSatisfy { $0.isASCII && ($0.properties.isAlphabetic || ("0"..."9").contains($0) || "!#$%&'*+-.^_`|~".unicodeScalars.contains($0)) }
    }
}

extension VersolaHttpResponseMessage {
    /// The whole response, body included. `URLSession` reports a repeated header already folded
    /// into one comma-separated value, so there is one pair per name; it has no reason phrase either.
    init(_ data: Data, _ response: HTTPURLResponse) {
        self.init(
            status: Int64(response.statusCode),
            reasonPhrase: nil,
            headers: response.allHeaderFields.compactMap { name, value in
                guard let name = name as? String, let value = value as? String else { return nil }
                return VersolaHttpHeaderMessage(name: name, value: value)
            },
            body: FlutterStandardTypedData(bytes: data)
        )
    }
}
