import Foundation
import os
import XCTest
@testable import OAuthClient
@testable import OAuthCore
@testable import VersolaEdge
@testable import VersolaSDK

/// `OAuthClient` has a `LoginOptions` of its own (the generic facade's), and these tests import it for the
/// stores and the key: the facade's is the one meant here.
typealias LoginOptions = VersolaSDK.LoginOptions

/// Constants for the facade's tests. Hosts are `example.com`, every value throwaway.
enum Sdk {
    static let edgeUrl = "https://id.example.com"
    static let issuer = "https://id.example.com"
    static let redirect = "https://app.example.com/callback"
    static let postLogout = "https://app.example.com/signed-out"
    static let authorizationEndpoint = "https://login.example.com/authorize"
    static let tokenEndpoint = "https://auth.example.com:8443/token"
    static let revocationEndpoint = "https://auth.example.com:8443/revoke"
    static let now = Date(timeIntervalSince1970: 1_800_000_000)
    static let fixedClock = Clock(now: { Sdk.now })
}

/// A DPoP key store in memory, so that no test touches the Keychain or the Secure Enclave.
final class MemoryKeyStore: DpopKeyStore {
    private let data = OSAllocatedUnfairLock<Data?>(initialState: nil)
    func load() throws -> Data? { data.withLock { $0 } }
    func save(_ value: Data) throws { data.withLock { $0 = value } }
    func delete() throws { data.withLock { $0 = nil } }
    var isEmpty: Bool { data.withLock { $0 == nil } }
}

/// What a scripted edge answers and what it was asked, by path. Only the four native endpoints exist:
/// anything else is a 404 the test then sees in `requests`.
actor ScriptedEdge: HTTPClient {
    struct Start: Sendable {
        let state: String
        let nonce: String
        let form: [(String, String)]
    }

    private(set) var requests: [HTTPRequest] = []
    private(set) var starts: [Start] = []
    private(set) var completes: [[(String, String)]] = []
    private(set) var revoked: [String] = []
    private(set) var issuedRefreshTokens: [String] = []

    /// The `sub` of each sign-in in turn; the last one repeats.
    var subjects = ["alice"]
    /// The `iss` of the ID tokens issued, which may carry a trailing slash.
    var idTokenIssuer = Sdk.issuer
    var audience: String

    init(audience: String) { self.audience = audience }
    var includeIdToken = true
    /// Replaces the claims of the ID token after the defaults are set (nil removes a claim).
    var claimOverrides: [String: Sendable?] = [:]
    /// The nonce to put in the ID token instead of the last start's, for a sign-in this edge did not start.
    var forcedNonce: String?
    var completeOverride: HTTPResponse?
    var startOverride: HTTPResponse?
    var refreshOverride: HTTPResponse?
    var revokeOverride: HTTPResponse?
    /// Held after `/native/complete` has been received and before it is answered: the server has the code
    /// and the caller can be cancelled meanwhile.
    var completeGate: Gate?
    /// Leaves `scope` out of the token response, which a provider may do when it granted what was asked.
    var omitScope = false
    func setOmitScope(_ value: Bool) { omitScope = value }

    func setCompleteGate(_ gate: Gate?) { completeGate = gate }
    func setAudience(_ audience: String) { self.audience = audience }
    func setSubjects(_ subjects: [String]) { self.subjects = subjects }
    func setIdTokenIssuer(_ issuer: String) { idTokenIssuer = issuer }
    func setIncludeIdToken(_ value: Bool) { includeIdToken = value }
    func setClaimOverrides(_ overrides: [String: Sendable?]) { claimOverrides = overrides }
    func setForcedNonce(_ nonce: String?) { forcedNonce = nonce }
    func setCompleteOverride(_ response: HTTPResponse?) { completeOverride = response }
    func setStartOverride(_ response: HTTPResponse?) { startOverride = response }
    func setRefreshOverride(_ response: HTTPResponse?) { refreshOverride = response }

    func requests(path prefix: String) -> [HTTPRequest] { requests.filter { $0.url.path.hasPrefix(prefix) } }
    func paths() -> [String] { requests.map { $0.url.path } }

    func send(_ request: HTTPRequest) async throws -> HTTPResponse {
        requests.append(request)
        let path = request.url.path
        let form = Self.decode(request)
        let json = ["Content-Type": "application/json"]
        if path.hasPrefix("/native/start/") {
            if let startOverride { return startOverride }
            let state = "edge-state-\(starts.count + 1)"
            starts.append(Start(state: state, nonce: form.first { $0.0 == "nonce" }?.1 ?? "", form: form))
            let body = #"{"client_id":"mobile-app","request_uri":"urn:ietf:params:oauth:request_uri:v1.kz-1.AbC_d-9","expires_in":90,"authorization_endpoint":"\#(Sdk.authorizationEndpoint)","state":"\#(state)","blob":"v1.kz-1.blob-\#(starts.count)","token_endpoint":"\#(Sdk.tokenEndpoint)","revocation_endpoint":"\#(Sdk.revocationEndpoint)"}"#
            return HTTPResponse(statusCode: 200, headers: json, body: Data(body.utf8))
        }
        if path.hasPrefix("/native/complete/") {
            completes.append(form)
            if let gate = completeGate { await gate.wait() }
            if let completeOverride { return completeOverride }
            let subject = subjects[min(completes.count - 1, subjects.count - 1)]
            let refreshToken = "rt-\(completes.count)"
            issuedRefreshTokens.append(refreshToken)
            let nonce = forcedNonce ?? starts.last?.nonce ?? ""
            var members: [String: Any] = [
                "access_token": "at-\(completes.count)", "token_type": "DPoP", "expires_in": 300,
                "refresh_token": refreshToken, "scope": "openid offline_access",
            ]
            if omitScope { members.removeValue(forKey: "scope") }
            if includeIdToken { members["id_token"] = idToken(subject: subject, nonce: nonce) }
            return HTTPResponse(statusCode: 200, headers: json, body: try JSONSerialization.data(withJSONObject: members))
        }
        if path.hasPrefix("/native/token/") {
            if let refreshOverride { return refreshOverride }
            return HTTPResponse(statusCode: 200, headers: json, body: Data(#"{"access_token":"at-refreshed","token_type":"DPoP","expires_in":300}"#.utf8))
        }
        if path.hasPrefix("/native/revoke/") {
            revoked.append(form.first { $0.0 == "token" }?.1 ?? "")
            return revokeOverride ?? HTTPResponse(statusCode: 200)
        }
        return HTTPResponse(statusCode: 404)
    }

    func setRevokeOverride(_ response: HTTPResponse?) { revokeOverride = response }

    /// A claims-only token: the signature is garbage on purpose, as an edge-relayed token's is not checked.
    private func idToken(subject: String, nonce: String) -> String {
        let at = Int(Sdk.now.timeIntervalSince1970)
        var claims: [String: Any?] = [
            "iss": idTokenIssuer, "sub": subject, "aud": audience, "exp": at + 3600, "iat": at - 10, "nonce": nonce,
        ]
        for (key, value) in claimOverrides { claims[key] = value }
        let header = Self.base64Url(Data(#"{"alg":"ES256","typ":"JWT"}"#.utf8))
        let payload = Self.base64Url(try! JSONSerialization.data(withJSONObject: claims.compactMapValues { $0 }, options: [.sortedKeys]))
        return "\(header).\(payload).\(Self.base64Url(Data("not a signature".utf8)))"
    }

    private static func base64Url(_ data: Data) -> String {
        data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }

    static func decode(_ request: HTTPRequest) -> [(String, String)] {
        String(decoding: request.body ?? Data(), as: UTF8.self).split(separator: "&").map { pair in
            let parts = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            return (String(parts[0]).removingPercentEncoding ?? "", (parts.count > 1 ? String(parts[1]).removingPercentEncoding : "") ?? "")
        }
    }

    static func proofClaims(_ request: HTTPRequest) -> [String: Any] {
        guard let proof = request.headers["DPoP"] else { return [:] }
        return proofClaims(header: proof)
    }

    static func proofClaims(header proof: String) -> [String: Any] {
        let segments = proof.split(separator: ".").map(String.init)
        guard segments.count == 3, let payload = JoseBase64Url.decode(segments[1]),
              let object = try? JSONSerialization.jsonObject(with: payload) as? [String: Any] else { return [:] }
        return object
    }
}

/// A browser that answers the authorization request with the redirect edge's start said to expect, and
/// the end-session request with the post-logout redirect; each can be held, bent or refused per test.
actor ScriptedBrowser: BrowserAuthorizationSession {
    private let edge: ScriptedEdge
    private(set) var opened: [URL] = []
    private(set) var options: [BrowserSessionOptions] = []
    /// The `iss` the redirect carries; nil omits it.
    var redirectIss: String? = Sdk.issuer
    var redirectState: String?
    var code = "v1.kz-2.Zz+/="
    /// Held until the test opens it: the browser is up and nothing has answered.
    var gate: Gate?
    var endSessionAnswers = true

    init(edge: ScriptedEdge) { self.edge = edge }

    func setRedirectIss(_ iss: String?) { redirectIss = iss }
    func setRedirectState(_ state: String?) { redirectState = state }
    func hold(_ gate: Gate) { self.gate = gate }
    func setEndSessionAnswers(_ value: Bool) { endSessionAnswers = value }

    func authorize(_ uri: URL, options: BrowserSessionOptions) async throws -> BrowserOutcome {
        opened.append(uri)
        self.options.append(options)
        if uri.path == "/logout" {
            guard endSessionAnswers else { return .userCancelled }
            let state = AuthorizationResponseValidator.parseQuery(uri)["state"] ?? ""
            return .redirect(URL(string: "\(Sdk.postLogout)?state=\(FormEncoding.percentEncode(state))")!)
        }
        if let gate { await gate.wait() }
        let state: String
        if let redirectState { state = redirectState } else { state = await edge.starts.last?.state ?? "" }
        var pairs = [("code", code), ("state", state)]
        if let redirectIss { pairs.append(("iss", redirectIss)) }
        return .redirect(URL(string: Sdk.redirect + "?" + FormEncoding.encode(pairs))!)
    }

    func awaitPendingRedirect() async throws -> BrowserOutcome {
        try await Task.sleep(nanoseconds: 3_600_000_000_000)
        throw CancellationError()
    }
}

/// The browser of a process a redirect cold-started: nothing is opened, and the redirect arrives when the test releases it.
final class ColdBrowser: BrowserAuthorizationSession, Sendable {
    private let outcome: BrowserOutcome
    private let channel = AsyncStream.makeStream(of: Void.self)
    init(_ outcome: BrowserOutcome) { self.outcome = outcome }
    func authorize(_ uri: URL, options: BrowserSessionOptions) async throws -> BrowserOutcome { throw CancellationError() }
    func awaitPendingRedirect() async throws -> BrowserOutcome {
        for await _ in channel.stream { break }
        try Task.checkCancellation()
        return outcome
    }
    func release() { channel.continuation.yield() }
}

/// A one-shot latch.
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

/// What a test builds a client from: the scripted edge and browser, the in-memory stores, a software key.
struct World: Sendable {
    let edge: ScriptedEdge
    let browser: ScriptedBrowser
    let credentials = InMemoryCredentialStore()
    let pending = InMemoryPendingAuthorizationStore()
    let endpoints = InMemoryEdgeEndpointsStore()
    let scopes = InMemoryGrantedScopeStore()
    let keys = MemoryKeyStore()
    let clientId: String
    let session: URLSession
    let logger = Warnings()

    init(session: URLSession = StubURLProtocol.session()) {
        // A client id per world: the registry is per process and keyed by it.
        let clientId = "mobile-\(UUID().uuidString.prefix(8))"
        self.clientId = clientId
        edge = ScriptedEdge(audience: clientId)
        browser = ScriptedBrowser(edge: edge)
        self.session = session
    }

    func configuration(
        edgeUrl: String = Sdk.edgeUrl, issuer: String? = nil, redirect: String = Sdk.redirect, postLogout: String? = Sdk.postLogout,
        requireHardwareKey: Bool = false, clientId: String? = nil
    ) throws -> VersolaConfiguration {
        try VersolaConfiguration(
            edgeUrl: edgeUrl, clientId: clientId ?? self.clientId, redirectUri: redirect, issuer: issuer, postLogoutRedirectUri: postLogout,
            requireHardwareKey: requireHardwareKey, logger: logger, urlSession: session
        )
    }

    func wiring(browser override: (any BrowserAuthorizationSession)? = nil, pending: (any PendingAuthorizationStore)? = nil) -> Versola.Wiring {
        let keys = self.keys
        return Versola.Wiring(
            browser: override ?? browser, credentialStore: credentials, pendingStore: pending ?? self.pending, endpointsStore: endpoints,
            grantedScopeStore: scopes, httpClient: edge,
            makeDpopKey: { requireHardware, logger, isGrantHeld in
                SecureEnclaveDpopKey(store: keys, requireHardware: requireHardware, logger: logger, secureEnclaveAvailable: false, isGrantHeld: isGrantHeld)
            },
            clock: Sdk.fixedClock
        )
    }

    func create(_ configuration: VersolaConfiguration? = nil, browser: (any BrowserAuthorizationSession)? = nil, pending: (any PendingAuthorizationStore)? = nil) async throws -> Versola {
        try await Versola.create(configuration: try configuration ?? self.configuration(), wiring: wiring(browser: browser, pending: pending))
    }
}

/// An `OAuthLogger` that keeps what it was told.
final class Warnings: OAuthLogger, Sendable {
    private let lines = OSAllocatedUnfairLock(initialState: [String]())
    var all: [String] { lines.withLock { $0 } }
    func info(_ message: String) { lines.withLock { $0.append(message) } }
    func warn(_ message: String) { lines.withLock { $0.append(message) } }
    func debug(_ message: String) { lines.withLock { $0.append(message) } }
}

/// Records the states a stream publishes, in order, collapsing nothing.
actor StateRecorder {
    private(set) var states: [SessionState] = []
    private var task: Task<Void, Never>?

    func start(_ stream: AsyncStream<SessionState>) {
        task = Task { for await state in stream { self.record(state) } }
    }

    private func record(_ state: SessionState) { states.append(state) }

    func stop() { task?.cancel() }
}

func thrown(_ body: () async throws -> some Any) async -> OAuthError? {
    do {
        _ = try await body()
        return nil
    } catch {
        return error as? OAuthError
    }
}

/// Polls, yielding between looks, until `condition` holds; bounded, so a regression fails the test
/// instead of hanging it. There is no sleep.
func waitUntil(_ message: String, file: StaticString = #filePath, line: UInt = #line, _ condition: @Sendable () async -> Bool) async {
    for _ in 0..<500_000 {
        if await condition() { return }
        await Task.yield()
    }
    XCTFail("timed out waiting for: \(message)", file: file, line: line)
}

/// A `URLProtocol` that answers from a closure on an ephemeral session, so no test reaches a network.
final class StubURLProtocol: URLProtocol {
    private struct State: Sendable {
        var handler: (@Sendable (URLRequest) -> (Int, [String: String], Data))?
        var requests: [URLRequest] = []
    }

    private static let state = OSAllocatedUnfairLock(initialState: State())

    static func install(_ handler: @escaping @Sendable (URLRequest) -> (Int, [String: String], Data)) {
        state.withLock { $0 = State(handler: handler) }
    }

    static func reset() { state.withLock { $0 = State() } }
    static var requests: [URLRequest] { state.withLock { $0.requests } }

    /// One session for the whole run: `Versola.create` compares the session of a second configuration by identity.
    private static let sharedSession: URLSession = {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [StubURLProtocol.self]
        return URLSession(configuration: configuration)
    }()

    static func session() -> URLSession { sharedSession }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        let request = self.request
        let handler = Self.state.withLock { state -> (@Sendable (URLRequest) -> (Int, [String: String], Data))? in
            state.requests.append(request)
            return state.handler
        }
        guard let url = request.url, let handler else {
            client?.urlProtocol(self, didFailWithError: URLError(.unsupportedURL))
            return
        }
        let (status, headers, body) = handler(request)
        let response = HTTPURLResponse(url: url, statusCode: status, httpVersion: "HTTP/1.1", headerFields: headers)!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: body)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}
