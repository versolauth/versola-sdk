import Foundation

/// A token endpoint answer (RFC 6749 §5.1), already checked for shape. Carries secrets:
/// `description` redacts everything.
package struct TokenResponse: Sendable, Equatable, CustomStringConvertible {
    package let accessToken: String
    package let tokenType: String
    /// Seconds, or 0 when the response declined to say (unknown, not expired).
    package let expiresIn: Int
    package let refreshToken: String?
    package let idToken: String?
    package let scope: String?
    /// The response's `Date` header: the server's clock, for ID-token validation.
    package let serverDate: Date?

    package init(accessToken: String, tokenType: String, expiresIn: Int, refreshToken: String?, idToken: String?, scope: String?, serverDate: Date? = nil) {
        self.accessToken = accessToken
        self.tokenType = tokenType
        self.expiresIn = expiresIn
        self.refreshToken = refreshToken
        self.idToken = idToken
        self.scope = scope
        self.serverDate = serverDate
    }

    package var description: String { "TokenResponse(\(tokenType), redacted)" }
}
