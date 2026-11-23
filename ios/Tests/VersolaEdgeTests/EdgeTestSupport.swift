import Foundation
import os
import XCTest
@testable import OAuthCore
@testable import VersolaEdge

/// Constants and fakes for the edge channel's tests. Hosts are `example.com`, values throwaway.
enum EdgeFixture {
    static let edgeUrl = URL(string: "https://id.example.com")!
    static let edgeOrigin = "https://id.example.com"
    static let clientId = "mobile-app"
    static let issuer = "https://id.example.com"
    static let redirect = "https://app.example.com/callback"
    static let startUrl = "https://id.example.com/native/start/mobile-app"
    static let completeUrl = "https://id.example.com/native/complete/mobile-app"
    static let tokenUrl = "https://id.example.com/native/token/mobile-app"
    static let revokeUrl = "https://id.example.com/native/revoke/mobile-app"
    /// Auth's endpoints on its own address: what the proofs are signed for, and never dialled.
    static let tokenEndpoint = "https://auth.example.com:8443/token"
    static let authOrigin = "https://auth.example.com:8443"
    static let revocationEndpoint = "https://auth.example.com:8443/revoke"
    /// What edge answered for the browser; deliberately not the issuer's `/authorize`.
    static let authorizationEndpoint = "https://login.example.com/authorize"
    static let requestUri = "urn:ietf:params:oauth:request_uri:v1.kz-1.AbC_d-9"
    static let now = Date(timeIntervalSince1970: 1_800_000_000)

    static var configuration: CoreConfiguration {
        CoreConfiguration(issuer: issuer, clientId: clientId, redirectUri: URL(string: redirect)!, postLogoutRedirectUri: nil)
    }

    /// A `/native/start` answer; any member can be replaced, or removed by passing `nil`.
    static func startAnswer(_ overrides: [String: Any?] = [:]) -> String {
        var members: [String: Any?] = [
            "client_id": clientId, "request_uri": requestUri, "expires_in": 90, "authorization_endpoint": authorizationEndpoint,
            "state": "edge-state-1", "blob": "v1.kz-1.aB-c_D.e~f", "token_endpoint": tokenEndpoint, "revocation_endpoint": revocationEndpoint,
        ]
        for (key, value) in overrides { members[key] = value }
        let object = members.compactMapValues { $0 }
        return String(decoding: try! JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes]), as: UTF8.self)
    }

    static func tokenAnswer(tokenType: String = "DPoP") -> String {
        #"{"access_token":"at-1","token_type":"\#(tokenType)","expires_in":300,"refresh_token":"rt-1","id_token":"idt","scope":"openid offline_access"}"#
    }

    static func proofSource() -> DpopProofFactory { DpopProofFactory(key: SoftwareDpopKey()) }

    static func answer(_ status: Int, _ headers: [String: String] = [:], _ body: String = "") -> HTTPResponse {
        HTTPResponse(statusCode: status, headers: headers, body: Data(body.utf8))
    }

    static func decodeForm(_ request: HTTPRequest) -> [(String, String)] {
        String(decoding: request.body ?? Data(), as: UTF8.self).split(separator: "&", omittingEmptySubsequences: true).map { pair in
            let parts = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            return (String(parts[0]).removingPercentEncoding ?? "", (parts.count > 1 ? String(parts[1]).removingPercentEncoding : "") ?? "")
        }
    }

    /// The claims of the proof a request carried.
    static func proofClaims(_ request: HTTPRequest) -> [String: Any] {
        guard let proof = request.headers["DPoP"] else { return [:] }
        let segments = proof.split(separator: ".").map(String.init)
        guard segments.count == 3, let payload = JoseBase64Url.decode(segments[1]),
              let object = try? JSONSerialization.jsonObject(with: payload) as? [String: Any] else { return [:] }
        return object
    }
}

/// An `HTTPClient` that answers from a queue (the last answer repeats) and records every request.
actor ScriptedHTTP: HTTPClient {
    enum Step: Sendable {
        case answer(HTTPResponse)
        case fail
    }

    private(set) var requests: [HTTPRequest] = []
    private var steps: [Step]
    private var index = 0

    init(_ answers: [HTTPResponse]) { steps = answers.map(Step.answer) }
    init(steps: [Step]) { self.steps = steps }

    func firstRequest() throws -> HTTPRequest {
        try XCTUnwrap(requests.first, "no request was sent")
    }

    func send(_ request: HTTPRequest) async throws -> HTTPResponse {
        requests.append(request)
        let step = steps[min(index, steps.count - 1)]
        index += 1
        switch step {
        case .answer(let response): return response
        case .fail: throw URLError(.notConnectedToInternet)
        }
    }
}

/// Virtual time for a retry budget, so that a repeat after a `Retry-After` needs no sleep.
final class RetryWorld: Sendable {
    private let seconds = OSAllocatedUnfairLock(initialState: 0.0)
    private let slept = OSAllocatedUnfairLock(initialState: [TimeInterval]())
    var delays: [TimeInterval] { slept.withLock { $0 } }

    var clock: Clock {
        Clock(now: { Date(timeIntervalSince1970: 1_700_000_000 + self.seconds.withLock { $0 }) }, uptime: { 5000 + self.seconds.withLock { $0 } })
    }

    struct NoJitter: RandomSource {
        func bytes(_ count: Int) -> [UInt8] { [UInt8](repeating: 0, count: count) }
    }

    func budget(cooldown: RetryCooldown? = nil) -> RetryBudget {
        RetryPolicy.default.newBudget(clock: clock, random: NoJitter(), cooldown: cooldown, sleep: { delay in
            self.slept.withLock { $0.append(delay) }
            self.seconds.withLock { $0 += delay }
        })
    }

    func within<T>(_ budget: RetryBudget, _ body: () async throws -> T) async throws -> T {
        try await OperationBudget.$current.withValue(budget) { try await body() }
    }
}

func thrown(_ body: () async throws -> some Any) async -> OAuthError? {
    do {
        _ = try await body()
        return nil
    } catch {
        return error as? OAuthError
    }
}
