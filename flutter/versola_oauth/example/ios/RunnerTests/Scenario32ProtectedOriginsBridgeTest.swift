import Foundation
import Network
import OAuthCore
import XCTest
import os
@testable import OAuthClient
@testable import versola_oauth

/// `32-protected-origins` through the bridge. The subject is the authenticated session, which
/// Flutter reaches as `OAuthClient.httpClient()`: Dart sends one `httpRequest` and the plugin runs it
/// with `authenticatedSession`, the SDK's own session, so each test below sends the request the way
/// the Dart client does (`DartSide.httpRequest`) and reads what reached the wire off the SDK's
/// transcript (the driver's session records every request, replays included).
///
/// Differences from the native twin: `create` accepts an empty `protectedOrigins` (the facade
/// demands origins of the authenticated session, not of the configuration), so the "constructing
/// with an empty or non-https set" assertion is the first request through the client, which is
/// refused before anything is sent: `httpClient()` returns synchronously and cannot ask native.
/// The DPoP half (htu without query, ath) is scenario 33's bridge test. `URLSession` reports a
/// repeated response header already folded into one value, and the virtual network answers with a
/// dictionary of headers, so the repeated-header assertion of the Android twin is not made here.
///
/// Two tests keep the pre-`httpClient()` shape on purpose: the token `accessToken()` returns is
/// accepted by the provider's resource (the escape hatch still works), and `create` still refuses a
/// `protectedOrigins` entry that is not an origin.
final class Scenario32ProtectedOriginsBridgeTest: BridgeConformance {
    /// The same server under another host name: the virtual network answers per origin string.
    private static let otherHostOrigin = "http://127.0.0.1:18080"
    private static let scriptedOrigin = "http://localhost:18084"

    /// A resource that answers from a script and records what it was sent.
    private final class Scripted: Sendable {
        private struct State: Sendable {
            var answers: [VirtualNetwork.StubAnswer]
            var requests: [(headers: [String: String], body: Data)] = []
        }
        private let state: OSAllocatedUnfairLock<State>
        init(_ answers: [VirtualNetwork.StubAnswer]) { state = OSAllocatedUnfairLock(initialState: State(answers: answers)) }
        var requests: [(headers: [String: String], body: Data)] { state.withLock { $0.requests } }
        func answer(_ request: URLRequest) -> VirtualNetwork.StubAnswer {
            let body = request.httpBody ?? request.httpBodyStream.map(VirtualNetwork.drain) ?? Data()
            return state.withLock {
                $0.requests.append((request.allHTTPHeaderFields ?? [:], body))
                return $0.answers.isEmpty ? VirtualNetwork.StubAnswer(status: 599) : $0.answers.removeFirst()
            }
        }
    }

    private func scripted(_ answers: [VirtualNetwork.StubAnswer]) -> Scripted {
        let script = Scripted(answers)
        network.resource(Self.scriptedOrigin) { request in script.answer(request) }
        return script
    }

    private func bearerChallenge(_ value: String) -> VirtualNetwork.StubAnswer {
        VirtualNetwork.StubAnswer(status: 401, headers: ["WWW-Authenticate": value])
    }

    func test32BridgeTheTokenThatCrossesIsAcceptedAtTheConfiguredOriginAndTheSdkSendsNothingThereItself() async throws {
        let bridge = try await bridge()
        try ok(await bridge.dart.login())
        let accessToken = try token(await bridge.dart.accessToken())
        let claims = try await bridge.dart.claims()
        let subject = try XCTUnwrap(claims).subject

        // The app attaches the token itself, as it would without httpClient(): the configured origin accepts it, with a path and a query.
        let (configuredBody, configured) = try await appCall(accessToken, ResourceServer.origin + "/api")
        let (_, withPathAndQuery) = try await appCall(accessToken, ResourceServer.origin + "/api/items?page=2")
        XCTAssertEqual(configured.statusCode, 200)
        XCTAssertEqual(withPathAndQuery.statusCode, 200)
        XCTAssertTrue(String(decoding: configuredBody, as: UTF8.self).contains(subject))
        XCTAssertEqual(accessToken.tokenType, "Bearer")
        // The SDK itself never contacted the resource, and a request the app makes without the token is not the SDK's to fix.
        XCTAssertFalse(network.transcript.contains { $0.url.hasPrefix(ResourceServer.origin) })
        let tokenPath = path(try await bridge.native.metadata().tokenEndpoint)
        XCTAssertEqual(network.matching("POST", tokenPath).count, 1)
    }

    func test32BridgeANonHttpsOriginAndAnOriginWithAPathAreRefusedByCreate() async throws {
        let plain = try await dart().create(message(protectedOrigins: ["http://api.example.com"]))
        assertError(try failure(plain), .configuration, "invalidConfiguration")
        let withPath = try await dart().create(message(protectedOrigins: ["https://api.example.com/v1"]))
        assertError(try failure(withPath), .configuration, "invalidConfiguration")
    }

    func test32BridgeHttpRequestAttachesTheTokenToTheConfiguredOriginWithAnyPathAndQueryAndToNothingElse() async throws {
        try await ResourceServer.install(network, origin: ResourceServer.secondOrigin)
        try await ResourceServer.install(network, origin: Self.otherHostOrigin)
        let bridge = try await bridge()
        try ok(await bridge.dart.login())
        let tokenPath = path(try await bridge.native.metadata().tokenEndpoint)

        let configured = try response(await bridge.dart.httpRequest(ResourceServer.origin + "/api"))
        let withPathAndQuery = try response(await bridge.dart.httpRequest(ResourceServer.origin + "/api/items?page=2"))
        // The same host on another port, and the same server under another host name.
        let otherPort = try response(await bridge.dart.httpRequest(ResourceServer.secondOrigin + "/api"))
        let otherHost = try response(await bridge.dart.httpRequest(Self.otherHostOrigin + "/api"))

        XCTAssertEqual(configured.status, 200)
        XCTAssertEqual(withPathAndQuery.status, 200)
        XCTAssertEqual(otherPort.status, 401)
        XCTAssertEqual(otherHost.status, 401)
        let claims = try await bridge.dart.claims()
        let subject = try XCTUnwrap(claims).subject
        XCTAssertTrue(String(decoding: configured.body.data, as: UTF8.self).contains(subject))
        let sent = network.transcript.filter { $0.url.contains("/api") }
        XCTAssertEqual(sent.count, 4)
        for entry in sent where entry.url.hasPrefix(ResourceServer.origin) {
            XCTAssertEqual(entry.header("Authorization")?.hasPrefix("Bearer "), true, entry.url)
        }
        for entry in sent where !entry.url.hasPrefix(ResourceServer.origin) {
            XCTAssertNil(entry.header("Authorization"), entry.url)
        }
        // A 401 from an origin that is not protected does not spend the refresh token.
        XCTAssertEqual(network.matching("POST", tokenPath).count, 1)
    }

    func test32BridgeARedirectFromAProtectedOriginIsReturnedWithItsLocationAndNotFollowed() async throws {
        let bridge = try await bridge()
        try ok(await bridge.dart.login())

        let redirected = try response(await bridge.dart.httpRequest(ResourceServer.origin + "/redirect"))

        XCTAssertEqual(redirected.status, 302)
        XCTAssertEqual(headerValues(redirected, "Location"), ["https://elsewhere.example.com/landing"])
        XCTAssertFalse(network.transcript.contains { $0.url.contains("elsewhere.example.com") })
        XCTAssertEqual(network.transcript.filter { $0.url.contains("/redirect") }.count, 1)
    }

    func test32BridgeAnAuthorizationHeaderTheAppSetOnAProtectedOriginIsReplacedByTheSdksAndLeftAloneElsewhere() async throws {
        try await ResourceServer.install(network, origin: ResourceServer.secondOrigin)
        let bridge = try await bridge()
        try ok(await bridge.dart.login())
        let appHeaders = [("Authorization", "Bearer app-supplied"), ("authorization", "Bearer app-supplied-too"), ("DPoP", "app-forged")]

        let protected = try response(await bridge.dart.httpRequest(ResourceServer.origin + "/api", headers: appHeaders))
        let unprotected = try response(await bridge.dart.httpRequest(ResourceServer.secondOrigin + "/api", headers: appHeaders))

        XCTAssertEqual(protected.status, 200, "the SDK's token is the one the resource saw")
        let own = try XCTUnwrap(network.transcript.first { $0.url.hasPrefix(ResourceServer.origin) && $0.url.contains("/api") })
        let authorization = try XCTUnwrap(own.header("Authorization"))
        XCTAssertTrue(authorization.hasPrefix("Bearer ") && !authorization.contains("app-supplied"), authorization)
        XCTAssertNil(own.header("DPoP"), "a bearer session sends no proof, and the app's is dropped")
        // Another origin is the app's: its headers go out as written and the 401 is returned, no refresh.
        XCTAssertEqual(unprotected.status, 401)
        let elsewhere = try XCTUnwrap(network.transcript.first { $0.url.hasPrefix(ResourceServer.secondOrigin) })
        XCTAssertEqual(elsewhere.header("Authorization"), "Bearer app-supplied,Bearer app-supplied-too")
        XCTAssertEqual(elsewhere.header("DPoP"), "app-forged")
        let tokenPath = path(try await bridge.native.metadata().tokenEndpoint)
        XCTAssertEqual(network.matching("POST", tokenPath).count, 1)
    }

    func test32BridgeOriginsGivenPerClientReplaceTheConfiguredOnesForThatClient() async throws {
        try await ResourceServer.install(network, origin: ResourceServer.secondOrigin)
        let bridge = try await bridge()
        try ok(await bridge.dart.login())

        let first = try response(await bridge.dart.httpRequest(ResourceServer.origin + "/api", origins: [ResourceServer.secondOrigin]))
        let other = try response(await bridge.dart.httpRequest(ResourceServer.secondOrigin + "/api", origins: [ResourceServer.secondOrigin]))

        XCTAssertEqual(first.status, 401, "the configured origin is not in this client's set, so it gets no token")
        XCTAssertEqual(other.status, 200)
        XCTAssertNil(network.transcript.first { $0.url.hasPrefix(ResourceServer.origin) && $0.url.contains("/api") }?.header("Authorization"))
        XCTAssertEqual(network.transcript.first { $0.url.hasPrefix(ResourceServer.secondOrigin) }?.header("Authorization")?.hasPrefix("Bearer "), true)
    }

    func test32BridgeAnEmptyOriginSetAndANonHttpsOriginAreRefusedWithInvalidConfigurationBeforeAnythingIsSent() async throws {
        let bridge = try await bridge()
        try ok(await bridge.dart.login())
        let sentBefore = network.transcript.count

        for origins in [[], ["http://api.example.com"], ["https://api.example.com/v1"]] {
            assertError(try failure(await bridge.dart.httpRequest(ResourceServer.origin + "/api", origins: origins)), .configuration, "invalidConfiguration")
        }
        XCTAssertEqual(network.transcript.count, sentBefore)
    }

    func test32BridgeAClientConfiguredWithNoProtectedOriginsRefusesTheRequestUnlessItNamesOrigins() async throws {
        let bridge = try await bridge(protectedOrigins: [])
        try ok(await bridge.dart.login())
        let sentBefore = network.transcript.count

        assertError(try failure(await bridge.dart.httpRequest(ResourceServer.origin + "/api")), .configuration, "invalidConfiguration")
        XCTAssertEqual(network.transcript.count, sentBefore)
        let named = try response(await bridge.dart.httpRequest(ResourceServer.origin + "/api", origins: [ResourceServer.origin]))
        XCTAssertEqual(named.status, 200)
    }

    func test32BridgeARequestThatIsNotAnHttpRequestIsRefusedWithAFixedTextThatDoesNotQuoteTheHeader() async throws {
        let bridge = try await bridge()
        try ok(await bridge.dart.login())

        let relative = try failure(await bridge.dart.httpRequest("/api"))
        let badHeader = try failure(await bridge.dart.httpRequest(ResourceServer.origin + "/api", headers: [("X-Bad", "Bearer s3cr3t\nX-Injected: y")]))
        let getWithBody = try failure(await bridge.dart.httpRequest(ResourceServer.origin + "/api", body: [1]))

        for error in [relative, badHeader, getWithBody] { assertError(error, .configuration, "invalidConfiguration") }
        XCTAssertFalse("\(badHeader)".contains("s3cr3t"))
        XCTAssertFalse(network.transcript.contains { $0.url.contains("/api") })
    }

    func test32BridgeA503WithRetryAfterIsReturnedAsTheResponseAfterExactlyOneRequest() async throws {
        let script = scripted([VirtualNetwork.StubAnswer(status: 503, headers: ["Retry-After": "7"])])
        let bridge = try await bridge()
        try ok(await bridge.dart.login())

        let unavailable = try response(await bridge.dart.httpRequest(Self.scriptedOrigin + "/unavailable", origins: [Self.scriptedOrigin]))

        XCTAssertEqual(unavailable.status, 503)
        XCTAssertEqual(headerValues(unavailable, "Retry-After"), ["7"])
        XCTAssertEqual(script.requests.count, 1)
    }

    func test32BridgeRequestBytesAndResponseBytesCrossUnchanged() async throws {
        let reply = Data((0..<256).map { UInt8(255 - $0) })
        let script = scripted([VirtualNetwork.StubAnswer(status: 200, headers: ["Content-Type": "application/octet-stream"], body: reply)])
        let bridge = try await bridge()
        try ok(await bridge.dart.login())
        let everyByte = (0..<256).map { UInt8($0) }

        let answer = try response(await bridge.dart.httpRequest(
            Self.scriptedOrigin + "/upload", method: "POST", headers: [("Content-Type", "application/octet-stream")], body: everyByte, origins: [Self.scriptedOrigin]
        ))

        let received = try XCTUnwrap(script.requests.first)
        XCTAssertEqual(received.body, Data(everyByte))
        XCTAssertEqual(received.headers["Content-Type"], "application/octet-stream")
        XCTAssertEqual(answer.status, 200)
        XCTAssertEqual(answer.body.data, reply)
    }

    func test32BridgeA401RefreshesOnceAndTheRequestIsReplayedWithItsBodyAndTheNewToken() async throws {
        let script = scripted([bearerChallenge("Bearer error=\"invalid_token\""), VirtualNetwork.StubAnswer(status: 200, body: Data("done".utf8))])
        let bridge = try await bridge()
        try ok(await bridge.dart.login())
        let tokenPath = path(try await bridge.native.metadata().tokenEndpoint)

        let answer = try response(await bridge.dart.httpRequest(Self.scriptedOrigin + "/orders", method: "POST", body: Array("item=1".utf8), origins: [Self.scriptedOrigin]))

        XCTAssertEqual(answer.status, 200)
        XCTAssertEqual(String(decoding: answer.body.data, as: UTF8.self), "done")
        XCTAssertEqual(script.requests.count, 2)
        XCTAssertEqual(String(decoding: script.requests[0].body, as: UTF8.self), "item=1")
        XCTAssertEqual(String(decoding: script.requests[1].body, as: UTF8.self), "item=1", "the body is sent again")
        XCTAssertNotEqual(script.requests[0].headers["Authorization"], script.requests[1].headers["Authorization"], "the replay carries the refreshed token")
        XCTAssertEqual(network.matching("POST", tokenPath).count, 2, "one refresh, spent once")
        XCTAssertEqual(network.matching("POST", tokenPath)[1].field("grant_type"), "refresh_token")
    }

    func test32BridgeASecond401AfterTheRefreshIsARefusedSessionNotASecondRefresh() async throws {
        let script = scripted([bearerChallenge("Bearer"), bearerChallenge("Bearer"), bearerChallenge("Bearer")])
        let bridge = try await bridge()
        try ok(await bridge.dart.login())
        let tokenPath = path(try await bridge.native.metadata().tokenEndpoint)

        let error = try failure(await bridge.dart.httpRequest(Self.scriptedOrigin + "/orders", origins: [Self.scriptedOrigin]))

        assertError(error, .reauthenticate, "sessionRejected")
        XCTAssertEqual(script.requests.count, 2)
        XCTAssertEqual(network.matching("POST", tokenPath).count, 2)
    }

    func test32BridgeAStepUpChallengeIsAStepUpErrorWithItsParametersAndNoRefresh() async throws {
        let script = scripted([bearerChallenge("Bearer error=\"insufficient_user_authentication\", acr_values=\"urn:example:mfa\", max_age=300")])
        let bridge = try await bridge()
        try ok(await bridge.dart.login())
        let tokenPath = path(try await bridge.native.metadata().tokenEndpoint)

        let error = try failure(await bridge.dart.httpRequest(Self.scriptedOrigin + "/transfer", origins: [Self.scriptedOrigin]))

        assertError(error, .stepUp, "stepUp")
        XCTAssertEqual(error.acrValues, ["urn:example:mfa"])
        XCTAssertEqual(error.maxAge, 300)
        XCTAssertEqual(script.requests.count, 1)
        XCTAssertEqual(network.matching("POST", tokenPath).count, 1, "no refresh: the token is valid, its authentication context is not")
    }

    func test32BridgeACallThatGetsNoHttpResponseIsATransportFailureNamingTheErrorOnly() async throws {
        let bridge = try await bridge()
        try ok(await bridge.dart.login())
        // Loopback passes through the virtual network to the real one; nothing listens on port 1.
        let closed = "http://localhost:1"

        let result = try await bridge.dart.httpRequest(closed + "/gone/s3cr3t-path", origins: [closed])

        let failure = try XCTUnwrap(result as? HttpTransportFailure, "expected a transport failure, got \(result)")
        XCTAssertTrue(failure.exception.hasPrefix("URLError("), failure.exception)
        XCTAssertFalse("\(result)".contains("s3cr3t-path"))
    }

    // MARK: no cache and no cookie jar

    /// A real HTTP server on loopback, because the URL loading system's cache and cookie handling live in
    /// its HTTP layer: a `URLProtocol` stand-in is never asked to use either, so it cannot show their absence.
    /// Every answer is cacheable (`public, max-age`) and sets a cookie; each request's headers are recorded.
    final class LoopbackServer: Sendable {
        private let listener: NWListener
        private let seen = OSAllocatedUnfairLock(initialState: [[String: String]]())
        let port: UInt16

        init() throws {
            listener = try NWListener(using: .tcp, on: .any)
            let ready = DispatchSemaphore(value: 0)
            listener.stateUpdateHandler = { if case .ready = $0 { ready.signal() } }
            listener.newConnectionHandler = { [seen] connection in
                connection.start(queue: .global())
                connection.receive(minimumIncompleteLength: 1, maximumLength: 65_536) { data, _, _, _ in
                    let text = String(decoding: data ?? Data(), as: UTF8.self)
                    var headers: [String: String] = [:]
                    for line in text.components(separatedBy: "\r\n").dropFirst() {
                        guard let colon = line.firstIndex(of: ":") else { continue }
                        headers[String(line[..<colon])] = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
                    }
                    seen.withLock { $0.append(headers) }
                    let body = "v"
                    let reply = "HTTP/1.1 200 OK\r\nCache-Control: public, max-age=3600\r\nSet-Cookie: srv=1; Path=/\r\nContent-Type: text/plain\r\nContent-Length: \(body.utf8.count)\r\nConnection: close\r\n\r\n\(body)"
                    connection.send(content: Data(reply.utf8), completion: .contentProcessed { _ in connection.cancel() })
                }
            }
            listener.start(queue: .global())
            guard ready.wait(timeout: .now() + 10) == .success, let bound = listener.port?.rawValue else { throw BridgeFailure("the loopback server did not start") }
            port = bound
        }

        deinit { listener.cancel() }
        var origin: String { "http://localhost:\(port)" }
        var requests: [[String: String]] { seen.withLock { $0 } }
    }

    /// The driver's virtual network for everything but the loopback server, which is left to the real HTTP layer.
    final class VirtualExceptLoopback: URLProtocol {
        nonisolated(unsafe) static var realPort: Int?
        override class func canInit(with request: URLRequest) -> Bool { request.url?.port != realPort }
        override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
        override func stopLoading() {}
        override func startLoading() { VirtualProtocols.load(self, record: true) }
    }

    func test32BridgeAnAnswerTheSessionCouldCacheIsNotServedInPlaceOfARequestAndNoCookieIsSent() async throws {
        let server = try LoopbackServer()
        VirtualExceptLoopback.realPort = Int(server.port)
        // The SDK's session as `URLSession.shared` is configured by default: a cache that serves a fresh
        // answer and a cookie jar that sends what it holds.
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [VirtualExceptLoopback.self]
        configuration.urlCache = URLCache(memoryCapacity: 4_000_000, diskCapacity: 0)
        configuration.requestCachePolicy = .useProtocolCachePolicy
        configuration.httpShouldSetCookies = true
        configuration.httpCookieAcceptPolicy = .always
        let session = URLSession(configuration: configuration)
        let jar = try XCTUnwrap(configuration.httpCookieStorage, "an ephemeral session has its own cookie jar")
        jar.setCookie(try XCTUnwrap(HTTPCookie(properties: [.domain: "localhost", .path: "/", .name: "sid", .value: "from-the-jar"])))

        // Control: the same session, asked directly, serves the second GET from its cache and sends the cookie.
        // Without this the assertions below could pass because nothing here can cache or send a cookie at all.
        let direct = URL(string: server.origin + "/direct")!
        _ = try await session.data(from: direct)
        _ = try await session.data(from: direct)
        XCTAssertEqual(server.requests.count, 1, "the control session must serve its second GET from the cache")
        XCTAssertEqual(server.requests.first?["Cookie"]?.contains("sid=from-the-jar"), true, "the control session must send its cookie: \(server.requests)")

        // The SDK on that session, asked for the same kind of request through the bridge: every one is sent, none with a cookie.
        let config = try OAuthConfiguration(
            issuer: proxyIssuer, clientId: Provider.clientId, redirectUri: Provider.redirectUri, postLogoutRedirectUri: Provider.postLogoutRedirectUri,
            scopes: provider.scopes, protectedOrigins: [server.origin], logger: logger, urlSession: session
        )
        _ = try await client(config)
        let dart = dart()
        let created = try await dart.create(message(protectedOrigins: [server.origin]))
        XCTAssertNil(created as? CreateFailure)
        try ok(await dart.login())
        let before = server.requests.count

        for _ in 0..<2 { _ = try response(await dart.httpRequest(server.origin + "/cacheable")) }

        let sent = Array(server.requests.dropFirst(before))
        XCTAssertEqual(sent.count, 2, "a GET the session could have answered from its cache is sent every time, so it carries its token and proof")
        for request in sent {
            XCTAssertNil(request["Cookie"], "no cookie from the jar: \(request)")
            XCTAssertEqual(request["Authorization"]?.hasPrefix("Bearer "), true)
        }
    }
}
