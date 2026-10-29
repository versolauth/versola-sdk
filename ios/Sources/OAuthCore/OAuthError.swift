import Foundation

/// The error taxonomy of `spec/errors.md`: four categories, and the category is the contract.
/// An app switches on the category first; the payload says what, within it, happened.
///
/// Mirrors Android's `VersolaError` case for case so that the conformance transcripts can be
/// compared across platforms. Nothing credential-shaped is ever carried here: a `description`
/// is safe to log.
public enum OAuthError: Error, Sendable, Equatable {
    /// Transient or user-driven: the app may retry, or ask the user again.
    case recoverable(Recoverable)
    /// The session is over; the user signs in again.
    case reauthenticate(Reauthenticate)
    /// RFC 9470: the resource server wants a stronger authentication context.
    case stepUp(acrValues: [String], maxAge: Int?)
    /// A deployment, integration or provider problem no retry fixes.
    case configuration(Configuration)

    public enum Recoverable: Sendable, Equatable {
        case userCancelled
        case systemCancelled
        case pendingRequestExpired
        case network(detail: String, attempts: Int, elapsedMillis: Int64)
        case unlockRequired
        case nonceLoop(origin: String)
    }

    public enum Reauthenticate: Sendable, Equatable {
        case authorizationDenied
        case interactionRequired(code: String)
        case credentialsInvalidated
        case grantRejected
        case sessionRejected
        case sessionExpired
    }

    public enum Configuration: Sendable, Equatable {
        case stateMismatch
        case issuerMismatch(expected: String, received: String?)
        case malformedAuthorizationResponse
        case authorizationRejected(code: String, description: String?)
        case tokenRequestRejected(code: String, description: String?)
        case tokenResponseMalformed(detail: String)
        case discoveryFieldMissing(field: String)
        case discoveryIssuerMismatch(configured: String, advertised: String)
        case discoveryMalformed(detail: String)
        case invalidConfiguration(detail: String)
        case noBrowserAvailable
        case idTokenRejected(IdTokenRejection)
        case userInfoRejected(detail: String)
        case providerUnsupported(capability: String)
        case hardwareBindingUnavailable(detail: String)
    }
}

/// Why an ID token was refused (`spec/oauth-sdk-api.md` section 11); scenarios 25 to 27.
public enum IdTokenRejection: String, Sendable, Equatable, CaseIterable {
    case signature, algorithm, issuer, audience, expired, issuedAt, nonce, authTime, malformed, accessTokenHash
}

extension OAuthError: CustomStringConvertible {
    public var description: String {
        switch self {
        case .recoverable(let cause): return "recoverable: \(cause)"
        case .reauthenticate(let reason): return "reauthenticate: \(reason)"
        case .stepUp(let acrValues, let maxAge): return "step-up required: acr_values=\(acrValues) max_age=\(maxAge.map(String.init) ?? "nil")"
        case .configuration(let detail): return "configuration: \(detail)"
        }
    }
}
