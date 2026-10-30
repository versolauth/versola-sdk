import Foundation
import os
import XCTest
@testable import OAuthCore

/// Fakes and builders for the authorization-leg tests. Everything is an actor or an immutable
/// value, so none of it needs `@unchecked Sendable`.
enum AuthzKit {
    static let issuer = "https://id.example.com"
    static let redirect = "https://app.example.com/callback"
    static let postLogout = "https://app.example.com/signed-out"
    /// A fixed "now" so no test reads the wall clock.
    static let now = Date(timeIntervalSince1970: 1_800_000_000)

    static var configuration: CoreConfiguration {
        CoreConfiguration(
            issuer: issuer, clientId: "client-123", redirectUri: URL(string: redirect)!,
            postLogoutRedirectUri: URL(string: postLogout)!
        )
    }

    static func metadata(
        endSession: Bool = true,
        challengeMethods: [String] = [],
        dpop: Bool = false,
        issSupported: Bool = false,
        parEndpoint: String? = nil,
        requirePar: Bool = false
    ) -> ProviderMetadata {
        ProviderMetadata(
            issuer: issuer,
            authorizationEndpoint: "\(issuer)/authorize",
            tokenEndpoint: "\(issuer)/token",
            endSessionEndpoint: endSession ? "\(issuer)/logout" : nil,
            codeChallengeMethodsSupported: challengeMethods,
            dpopSigningAlgValuesSupported: dpop ? ["ES256"] : [],
            authorizationResponseIssParameterSupported: issSupported,
            pushedAuthorizationRequestEndpoint: parEndpoint,
            requirePushedAuthorizationRequests: requirePar
        )
    }

    static func pending(
        state: String = "state-1", createdAt: Date = now, issRequired: Bool = false, maxAge: Int? = nil
    ) -> PendingAuthorizationRequest {
        PendingAuthorizationRequest(
            state: state, nonce: "nonce-1", codeVerifier: String(repeating: "v", count: 43),
            scopes: ["openid"], redirectUri: redirect, maxAge: maxAge, createdAt: createdAt, issRequired: issRequired
        )
    }

    /// The redirect a provider would send back for `authorizationURI`, carrying its `state`.
    static func redirect(
        answering authorizationURI: URL, code: String? = "code-1", iss: String? = issuer,
        state overrideState: String? = nil, extra: [(String, String)] = []
    ) -> URL {
        var pairs: [(String, String)] = []
        if let code { pairs.append(("code", code)) }
        if let state = overrideState ?? AuthorizationResponseValidator.stateOf(authorizationURI) {
            pairs.append(("state", state))
        }
        if let iss { pairs.append(("iss", iss)) }
        pairs += extra
        return URL(string: redirect + "?" + FormEncoding.encode(pairs))!
    }

    /// Polls, yielding between looks, until `condition` holds. Bounded, so a regression fails
    /// the test instead of hanging it; there is no sleep.
    static func waitUntil(
        _ message: String, file: StaticString = #filePath, line: UInt = #line,
        _ condition: @Sendable () async -> Bool
    ) async {
        for _ in 0..<200_000 {
            if await condition() { return }
            await Task.yield()
        }
        XCTFail("timed out waiting for: \(message)", file: file, line: line)
    }
}

/// A one-shot latch for holding a fake collaborator mid-call.
actor Gate {
    private var isOpen = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func wait() async {
        if isOpen { return }
        await withCheckedContinuation { waiters.append($0) }
    }

    func open() {
        isOpen = true
        for waiter in waiters { waiter.resume() }
        waiters = []
    }
}

/// An `HTTPClient` driven by a closure, recording what it was sent.
actor RecordingHTTP: HTTPClient {
    private(set) var requests: [HTTPRequest] = []
    private let handler: @Sendable (HTTPRequest) async throws -> HTTPResponse

    init(_ handler: @escaping @Sendable (HTTPRequest) async throws -> HTTPResponse) {
        self.handler = handler
    }

    func send(_ request: HTTPRequest) async throws -> HTTPResponse {
        requests.append(request)
        return try await handler(request)
    }

    static func json(_ status: Int, _ body: String) -> RecordingHTTP {
        RecordingHTTP { _ in HTTPResponse(statusCode: status, body: Data(body.utf8)) }
    }
}

struct TransportFailure: Error {}

/// An in-memory pending store that counts what was done to it.
actor MemoryPendingStore: PendingAuthorizationStore {
    private(set) var stored: PendingAuthorizationRequest?
    private(set) var saveCount = 0
    private(set) var clearCount = 0

    init(_ initial: PendingAuthorizationRequest? = nil) { stored = initial }

    func save(_ request: PendingAuthorizationRequest) async throws {
        saveCount += 1
        stored = request
    }

    func load() async throws -> PendingAuthorizationRequest? { stored }

    func clear() async throws {
        clearCount += 1
        stored = nil
    }
}

/// A browser whose behaviour is a closure. `awaitPendingRedirect` by default waits until
/// cancelled, like a real one with nothing delivered.
actor ScriptedBrowser: BrowserAuthorizationSession {
    typealias OnAuthorize = @Sendable (URL, BrowserSessionOptions) async throws -> BrowserOutcome
    typealias OnAwait = @Sendable (_ opened: [URL]) async throws -> BrowserOutcome

    private(set) var opened: [URL] = []
    private(set) var options: [BrowserSessionOptions] = []
    private(set) var awaitCalls = 0
    private let onAuthorize: OnAuthorize
    private let onAwait: OnAwait

    init(
        onAuthorize: @escaping OnAuthorize,
        onAwait: @escaping OnAwait = { _ in
            try await Task.sleep(nanoseconds: 3_600_000_000_000)
            throw CancellationError()
        }
    ) {
        self.onAuthorize = onAuthorize
        self.onAwait = onAwait
    }

    func authorize(_ uri: URL, options: BrowserSessionOptions) async throws -> BrowserOutcome {
        opened.append(uri)
        self.options.append(options)
        return try await onAuthorize(uri, options)
    }

    func awaitPendingRedirect() async throws -> BrowserOutcome {
        awaitCalls += 1
        return try await onAwait(opened)
    }

    /// Answers every authorization with the redirect it asked for.
    static func answering() -> ScriptedBrowser {
        ScriptedBrowser { uri, _ in .redirect(AuthzKit.redirect(answering: uri)) }
    }

    static func outcome(_ outcome: BrowserOutcome) -> ScriptedBrowser {
        ScriptedBrowser { _, _ in outcome }
    }

    static func failing(_ error: Error) -> ScriptedBrowser {
        ScriptedBrowser { _, _ in throw error }
    }
}

/// A browser that stays open until the test answers it, one authorization at a time.
actor GatedBrowser: BrowserAuthorizationSession {
    private(set) var opened: [URL] = []
    private var waiting: [CheckedContinuation<BrowserOutcome, Error>] = []

    func authorize(_ uri: URL, options: BrowserSessionOptions) async throws -> BrowserOutcome {
        opened.append(uri)
        return try await withCheckedThrowingContinuation { waiting.append($0) }
    }

    func awaitPendingRedirect() async throws -> BrowserOutcome { throw CancellationError() }

    /// Answers the oldest open authorization.
    func resolveNext(_ outcome: BrowserOutcome) {
        waiting.removeFirst().resume(returning: outcome)
    }
}

/// Records one value from inside a closure that cannot capture a mutable local.
actor Box<Value: Sendable> {
    private(set) var value: Value
    init(_ initial: Value) { value = initial }
    func set(_ next: Value) { value = next }
}

struct FixedDpopSource: DpopProofSource {
    var jkt = "jkt-example-thumbprint"
    func thumbprint() async throws -> String { jkt }
    func proof(method: String, url: URL, nonce: String?, accessToken: String?) async throws -> String { "proof" }
    func observe(nonce: String, origin: String) async {}
    func nonce(for origin: String) async -> String? { nil }
    func clearNonces() async {}
}

/// A starter that returns a fixed browser URI and a pending request with an extension.
struct FixedStarter: AuthorizationStarter {
    var bindsDpopKeyItself = false
    func start(request: AuthorizationRequest, metadata: ProviderMetadata, now: Date) async throws
        -> StartedAuthorization {
        var pending = request.toPending(createdAt: now, issRequired: true)
        pending = PendingAuthorizationRequest(
            state: pending.state, nonce: pending.nonce, codeVerifier: pending.codeVerifier,
            scopes: pending.scopes, redirectUri: pending.redirectUri, createdAt: now,
            issRequired: true, extensions: ["blob": "sealed"]
        )
        return StartedAuthorization(
            pending: pending,
            browserUri: URL(string: "https://id.example.com/authorize?client_id=c&request_uri=urn%3Ax&state=\(pending.state)")!
        )
    }
}

/// A clock the test moves, wall and continuous together, handed to the code under test as a `Clock`.
final class ManualClock: Sendable {
    private let wall = OSAllocatedUnfairLock(initialState: Date(timeIntervalSince1970: 1_800_000_000))
    private let uptime = OSAllocatedUnfairLock(initialState: 1000.0)

    var clock: Clock { Clock(now: { self.wall.withLock { $0 } }, uptime: { self.uptime.withLock { $0 } }) }

    func advance(_ seconds: TimeInterval) {
        wall.withLock { $0 = $0.addingTimeInterval(seconds) }
        uptime.withLock { $0 += seconds }
    }
}
