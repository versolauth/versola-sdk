import os
@testable import OAuthClient

/// An `OAuthLogger` that keeps what it was told, for asserting on warnings.
final class RecordingLogger: OAuthLogger {
    private let lines = OSAllocatedUnfairLock<[String]>(initialState: [])
    func info(_ message: String) {}
    func warn(_ message: String) { lines.withLock { $0.append(message) } }
    var warnings: [String] { lines.withLock { $0 } }
}
