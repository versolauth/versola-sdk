import Foundation

/// A token endpoint answer (RFC 6749 §5.1), already checked for shape. Carries secrets:
/// `description` redacts everything.
public struct TokenResponse: Sendable, Equatable, CustomStringConvertible {
    public let accessToken: String
    public let tokenType: String
    /// Seconds, or 0 when the response declined to say (unknown, not expired).
    public let expiresIn: Int
    public let refreshToken: String?
    public let idToken: String?
    public let scope: String?
    /// The response's `Date` header: the server's clock, for ID-token validation.
    public let serverDate: Date?

    public init(accessToken: String, tokenType: String, expiresIn: Int, refreshToken: String?, idToken: String?, scope: String?, serverDate: Date? = nil) {
        self.accessToken = accessToken
        self.tokenType = tokenType
        self.expiresIn = expiresIn
        self.refreshToken = refreshToken
        self.idToken = idToken
        self.scope = scope
        self.serverDate = serverDate
    }

    public var description: String { "TokenResponse(\(tokenType), redacted)" }
}
