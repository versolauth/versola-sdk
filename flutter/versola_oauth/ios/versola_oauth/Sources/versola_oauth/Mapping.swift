// Type conversion between the Pigeon messages and the SDK's public types. Nothing here decides
// anything: a value the SDK refuses is refused by the SDK, and the refusal is what crosses.
import Foundation
import OAuthClient

extension ConfigurationMessage {
    func toConfiguration() throws -> OAuthConfiguration {
        try OAuthConfiguration(
            issuer: issuer,
            endpoints: endpoints.map {
                ProviderEndpoints(
                    issuer: $0.issuer,
                    authorizationEndpoint: $0.authorizationEndpoint,
                    tokenEndpoint: $0.tokenEndpoint,
                    jwksUri: $0.jwksUri,
                    userinfoEndpoint: $0.userinfoEndpoint,
                    revocationEndpoint: $0.revocationEndpoint,
                    endSessionEndpoint: $0.endSessionEndpoint,
                    pushedAuthorizationRequestEndpoint: $0.pushedAuthorizationRequestEndpoint,
                    idTokenSigningAlgValuesSupported: $0.idTokenSigningAlgValuesSupported
                )
            },
            clientId: clientId,
            redirectUri: redirectUri,
            postLogoutRedirectUri: postLogoutRedirectUri,
            scopes: Set(scopes),
            tokenBinding: {
                switch tokenBinding {
                case .bearer: return .bearer
                case .dpop: return .dpop(required: false)
                case .dpopRequireHardware: return .dpop(required: true)
                }
            }(),
            pushedAuthorization: {
                switch pushedAuthorization {
                case .never: return .never
                case .whenAdvertised: return .whenAdvertised
                case .required: return .required
                }
            }(),
            protectedOrigins: Set(protectedOrigins),
            endSessionEndpoint: endSessionEndpoint,
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
            unlockPolicy: unlockPolicy == .none ? .none : .onAppUnlock,
            clockSkewTolerance: TimeInterval(clockSkewToleranceSeconds)
        )
    }
}

extension LoginOptionsMessage {
    func toLoginOptions() throws -> LoginOptions {
        try LoginOptions(
            scopes: scopes.map(Set.init),
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
            acrValues: acrValues,
            maxAge: maxAge.map(Int.init),
            resources: resources,
            extraParameters: extraParameters,
            ephemeralBrowser: ephemeralBrowser
        )
    }
}

extension SessionState {
    func toMessage() -> SessionStateMessage {
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
    func toErrorMessage() -> ErrorMessage {
        if let error = self as? OAuthError { return error.toMessage() }
        let name = String(describing: type(of: self))
        var m = ErrorMessage(category: .configuration, kind: "invalidConfiguration", message: "configuration: unexpected \(name)")
        m.detail = "unexpected \(name)"
        return m
    }
}

extension OAuthError {
    /// Flattens the taxonomy for the wire. `category` is the contract; `kind` is the case name
    /// in the spelling Dart's enums use, so the sealed hierarchy is rebuilt case for case. The
    /// text is the SDK's own description, which never carries a credential (`security.md`).
    func toMessage() -> ErrorMessage {
        var m: ErrorMessage
        switch self {
        case .recoverable(let cause):
            m = ErrorMessage(category: .recoverable, kind: "", message: description)
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
            }
        case .reauthenticate(let reason):
            m = ErrorMessage(category: .reauthenticate, kind: "", message: description)
            switch reason {
            case .authorizationDenied: m.kind = "authorizationDenied"
            case .interactionRequired(let code): m.kind = "interactionRequired"; m.code = code
            case .credentialsInvalidated: m.kind = "credentialsInvalidated"
            case .grantRejected: m.kind = "grantRejected"
            case .sessionRejected: m.kind = "sessionRejected"
            case .sessionExpired: m.kind = "sessionExpired"
            }
        case .stepUp(let acrValues, let maxAge):
            m = ErrorMessage(category: .stepUp, kind: "stepUp", message: description)
            m.acrValues = acrValues
            m.maxAge = maxAge.map(Int64.init)
        case .configuration(let detail):
            m = ErrorMessage(category: .configuration, kind: "", message: description)
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
            }
        }
        return m
    }
}
