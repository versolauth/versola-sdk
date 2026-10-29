import Foundation
import os

/// The default logger: warnings only, to the unified log under subsystem `versola.oauth`
/// (`spec/oauth-sdk-api.md` section 15). An app that wants more, or elsewhere, passes its own
/// `OAuthLogger` in the configuration.
public struct OSLogLogger: OAuthLogger {
    private let logger = Logger(subsystem: "versola.oauth", category: "OAuthClient")

    public init() {}

    /// Dropped: the default level carries warnings only.
    public func info(_ message: String) {}

    /// Logged at `.error` level and public, which is safe because a message never carries a
    /// token, code, verifier, `state`, `nonce`, proof or claim value (`security.md`); without
    /// `.public` the unified log would redact the text to `<private>` and a warning that
    /// nobody can read is not a warning.
    public func warn(_ message: String) {
        logger.error("\(message, privacy: .public)")
    }
}
