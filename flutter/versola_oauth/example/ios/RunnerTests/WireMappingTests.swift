import Flutter
import Foundation
import OAuthClient
import XCTest

@testable import versola_oauth

/// The Swift half of the plugin is glue, and what is worth a unit test in it is the wire: every
/// `OAuthError` case keeps its category and payload, and nothing that is not an `OAuthError`
/// carries its text across. The scenarios run against a real provider are the native SDK's own
/// tier (`conformance/README.md`); `flutter test` proves the Dart half against a mocked channel.
final class WireMappingTests: XCTestCase {
    func testEveryCategoryKeepsItsKindAndPayload() {
        let network = OAuthError.recoverable(.network(detail: "timeout", attempts: 3, elapsedMillis: 1200)).toMessage()
        XCTAssertEqual(network.category, .recoverable)
        XCTAssertEqual(network.kind, "network")
        XCTAssertEqual(network.detail, "timeout")
        XCTAssertEqual(network.attempts, 3)
        XCTAssertEqual(network.elapsedMillis, 1200)

        let limited = OAuthError.recoverable(.server(status: 429, retryAfterMillis: 7000, attempts: 1, elapsedMillis: 40)).toMessage()
        XCTAssertEqual(limited.category, .recoverable)
        XCTAssertEqual(limited.kind, "server")
        XCTAssertEqual(limited.status, 429)
        XCTAssertEqual(limited.retryAfterMillis, 7000)
        XCTAssertEqual(limited.attempts, 1)
        XCTAssertEqual(limited.elapsedMillis, 40)
        XCTAssertNil(limited.detail, "a server answer carries its status, never its body or a detail string")

        let unavailable = OAuthError.recoverable(.server(status: 503, retryAfterMillis: nil, attempts: 3, elapsedMillis: 1750)).toMessage()
        XCTAssertEqual(unavailable.kind, "server")
        XCTAssertEqual(unavailable.status, 503)
        XCTAssertNil(unavailable.retryAfterMillis, "no Retry-After stays absent across the bridge")
        XCTAssertEqual(unavailable.attempts, 3)

        // A call the cooldown refused sent nothing: zero attempts, and what is left of the wait.
        let cooling = OAuthError.recoverable(.server(status: 429, retryAfterMillis: 20_000, attempts: 0, elapsedMillis: 0)).toMessage()
        XCTAssertEqual(cooling.attempts, 0)
        XCTAssertEqual(cooling.retryAfterMillis, 20_000)

        let interaction = OAuthError.reauthenticate(.interactionRequired(code: "login_required")).toMessage()
        XCTAssertEqual(interaction.category, .reauthenticate)
        XCTAssertEqual(interaction.kind, "interactionRequired")
        XCTAssertEqual(interaction.code, "login_required")

        let stepUp = OAuthError.stepUp(acrValues: ["urn:acr:mfa"], maxAge: 300).toMessage()
        XCTAssertEqual(stepUp.category, .stepUp)
        XCTAssertEqual(stepUp.acrValues, ["urn:acr:mfa"])
        XCTAssertEqual(stepUp.maxAge, 300)

        let rejected = OAuthError.configuration(.tokenRequestRejected(code: "invalid_grant", description: "expired")).toMessage()
        XCTAssertEqual(rejected.category, .configuration)
        XCTAssertEqual(rejected.kind, "tokenRequestRejected")
        XCTAssertEqual(rejected.code, "invalid_grant")
        XCTAssertEqual(rejected.errorDescription, "expired")

        let idToken = OAuthError.configuration(.idTokenRejected(.accessTokenHash)).toMessage()
        XCTAssertEqual(idToken.kind, "idTokenRejected")
        XCTAssertEqual(idToken.idTokenRejection, "accessTokenHash")
    }

    func testAnErrorThatIsNotAnSdkErrorCrossesAsAConfigurationNamingOnlyItsType() {
        struct Leaky: Error, CustomStringConvertible {
            var description: String { "refresh_token=do-not-leak" }
        }
        let message = Leaky().toErrorMessage()
        XCTAssertEqual(message.category, .configuration)
        XCTAssertEqual(message.kind, "invalidConfiguration")
        XCTAssertEqual(message.detail, "unexpected Leaky")
        XCTAssertFalse(message.message.contains("do-not-leak"))

        let foundation = NSError(domain: "x", code: 1, userInfo: [NSLocalizedDescriptionKey: "do-not-leak"]).toErrorMessage()
        XCTAssertFalse(foundation.message.contains("do-not-leak"))
        XCTAssertFalse((foundation.detail ?? "").contains("do-not-leak"))
    }

    func testTheSevenSessionStatesMapOneToOneAndInOrder() {
        let states: [SessionState] = [.unauthenticated, .authorizing, .authenticated, .refreshing, .stepUpRequired, .locked, .loggingOut]
        XCTAssertEqual(states.map { $0.toMessage().rawValue }, Array(0..<7))
    }

    // MARK: HTTP

    private func request(
        method: String = "GET", url: String = "https://api.example.com/items?page=2",
        headers: [(String, String)] = [], body: [UInt8]? = nil
    ) -> HttpRequestMessage {
        HttpRequestMessage(
            method: method, url: url, headers: headers.map { HttpHeaderMessage(name: $0.0, value: $0.1) },
            body: body.map { FlutterStandardTypedData(bytes: Data($0)) }
        )
    }

    private func refused(_ message: HttpRequestMessage, file: StaticString = #filePath, line: UInt = #line) -> String? {
        do {
            _ = try message.toURLRequest()
            XCTFail("expected the request to be refused", file: file, line: line)
            return nil
        } catch let error as OAuthError {
            guard case .configuration(.invalidConfiguration(let detail)) = error else {
                XCTFail("expected invalidConfiguration, got \(error)", file: file, line: line)
                return nil
            }
            return detail
        } catch {
            XCTFail("expected an OAuthError, got \(error)", file: file, line: line)
            return nil
        }
    }

    func testARequestKeepsItsMethodUrlHeadersAndBytes() throws {
        let sent = try request(method: "POST", headers: [("X-Trace", "abc"), ("Content-Type", "application/json")], body: Array("payload".utf8)).toURLRequest()

        XCTAssertEqual(sent.httpMethod, "POST")
        XCTAssertEqual(sent.url?.absoluteString, "https://api.example.com/items?page=2")
        XCTAssertEqual(sent.value(forHTTPHeaderField: "x-trace"), "abc")
        XCTAssertEqual(sent.value(forHTTPHeaderField: "Content-Type"), "application/json")
        XCTAssertEqual(sent.httpBody, Data("payload".utf8))
    }

    func testARepeatedRequestHeaderKeepsEveryValue() throws {
        let sent = try request(headers: [("Accept", "a/b"), ("accept", "c/d")]).toURLRequest()

        XCTAssertEqual(sent.value(forHTTPHeaderField: "Accept"), "a/b,c/d")
    }

    func testTheMappingAddsNoAuthorizationAndKeepsTheAppsOwn() throws {
        // Replacing it on a protected origin is the SDK session's rule; on any other origin the app's
        // header must reach the wire as written, so the glue neither adds nor drops one.
        let none = try request().toURLRequest()
        XCTAssertNil(none.value(forHTTPHeaderField: "Authorization"))
        XCTAssertNil(none.value(forHTTPHeaderField: "DPoP"))
        let own = try request(headers: [("Authorization", "Bearer app-own")]).toURLRequest()
        XCTAssertEqual(own.value(forHTTPHeaderField: "Authorization"), "Bearer app-own")
    }

    func testAnEmptyBodyIsNoBodyAndABodyOnGetOrHeadIsRefusedRatherThanDropped() throws {
        XCTAssertNil(try request(method: "POST", body: []).toURLRequest().httpBody)
        XCTAssertNil(try request(method: "GET", body: []).toURLRequest().httpBody)
        XCTAssertNotNil(refused(request(method: "GET", body: [1])))
        XCTAssertNotNil(refused(request(method: "HEAD", body: [1])))
    }

    func testARelativeUrlANonHttpSchemeAndAMissingHostAreRefusedWithoutEchoingThem() {
        // `ws://` is the input under test, a scheme the bridge must refuse, not a connection the test opens.
        // nosemgrep: javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket
        for url in ["/items", "ftp://api.example.com/x", "ws://api.example.com/x", "https:///x", ""] {
            let detail = refused(request(url: url))
            XCTAssertFalse(url.isEmpty ? false : (detail ?? "").contains(url), url)
        }
    }

    func testAMalformedHeaderIsRefusedWithAFixedTextThatDoesNotQuoteItsValue() {
        for header in [("Authorization", "Bearer s3cr3t\r\nX: y"), ("Bad Name", "x"), ("X-Nul", "a\0b"), ("", "x")] {
            let detail = refused(request(headers: [header]))
            XCTAssertFalse((detail ?? "").contains("s3cr3t"))
        }
    }

    func testAResponseKeepsStatusBytesAndHeaders() throws {
        let url = URL(string: "https://api.example.com/")!
        let response = try XCTUnwrap(HTTPURLResponse(url: url, statusCode: 429, httpVersion: "HTTP/1.1", headerFields: ["Retry-After": "7", "WWW-Authenticate": "Bearer realm=\"a\", DPoP algs=\"ES256\""]))

        let message = HttpResponseMessage(Data([0, 1, 2, 3]), response)

        XCTAssertEqual(message.status, 429)
        XCTAssertNil(message.reasonPhrase, "URLSession reports none")
        XCTAssertEqual(message.body.data, Data([0, 1, 2, 3]))
        XCTAssertEqual(Dictionary(uniqueKeysWithValues: message.headers.map { ($0.name.lowercased(), $0.value) }), [
            "retry-after": "7", "www-authenticate": "Bearer realm=\"a\", DPoP algs=\"ES256\"",
        ])
    }

    func testARequestReadsNoCacheAndHandlesNoCookies() throws {
        let sent = try request().toURLRequest()

        XCTAssertEqual(sent.cachePolicy, .reloadIgnoringLocalAndRemoteCacheData)
        XCTAssertFalse(sent.httpShouldHandleCookies)
    }

    func testTheSdkSessionKeepsNothingAndTheConfigurationUsesIt() throws {
        let configuration = NetworkSession.shared.configuration
        XCTAssertNil(configuration.urlCache)
        XCTAssertNil(configuration.httpCookieStorage)
        XCTAssertNil(configuration.urlCredentialStorage)
        XCTAssertFalse(configuration.httpShouldSetCookies)
        XCTAssertEqual(configuration.requestCachePolicy, .reloadIgnoringLocalAndRemoteCacheData)

        let message = ConfigurationMessage(
            issuer: "https://id.example.com", clientId: "app", redirectUri: "https://app.example.com/oauth", scopes: ["openid"],
            tokenBinding: .bearer, pushedAuthorization: .whenAdvertised, protectedOrigins: [], unlockPolicy: .none, clockSkewToleranceSeconds: 60
        )
        XCTAssertTrue(try message.toConfiguration().urlSession === NetworkSession.shared)
    }

    func testANonAsciiOrControlCharacterInAHeaderValueIsRefusedAsOnAndroidWithoutQuotingIt() {
        for value in ["Bearer s3cr3t\u{e9}", "Bearer s3cr3t\u{7f}", "Bearer s3cr3t\u{1F600}"] {
            let detail = refused(request(headers: [("Authorization", value)]))
            XCTAssertFalse((detail ?? "").contains("s3cr3t"))
        }
        // Visible ASCII, space and tab are fine.
        XCTAssertNoThrow(try request(headers: [("X-Ok", "a b\tc ~!")]).toURLRequest())
    }
}
