import XCTest
@testable import OAuthClient

final class URLSessionHTTPClientTests: XCTestCase {
    private let url = URL(string: "https://auth.example.com/token?code=abc")!

    override func tearDown() {
        StubURLProtocol.reset()
        super.tearDown()
    }

    func testResponseCarriesStatusBodyAndLowerCasedHeaders() async throws {
        StubURLProtocol.install { _ in
            .response(status: 200, headers: ["Content-Type": "application/json", "DPoP-Nonce": "n1"], body: Data("{}".utf8))
        }
        let client = URLSessionHTTPClient(session: StubURLProtocol.session())
        let response = try await client.send(HTTPRequest(method: .get, url: url))
        XCTAssertEqual(response.statusCode, 200)
        XCTAssertEqual(response.body, Data("{}".utf8))
        XCTAssertEqual(response.headers["content-type"], "application/json")
        XCTAssertEqual(response.header("DPoP-Nonce"), "n1")
    }

    func testRequestCarriesMethodHeadersAndBody() async throws {
        StubURLProtocol.install { _ in .response(status: 204) }
        let client = URLSessionHTTPClient(session: StubURLProtocol.session())
        let body = Data("grant_type=refresh_token".utf8)
        _ = try await client.send(HTTPRequest(
            method: .post, url: url, headers: ["Content-Type": "application/x-www-form-urlencoded"], body: body
        ))
        let sent = try XCTUnwrap(StubURLProtocol.requests.first)
        XCTAssertEqual(sent.httpMethod, "POST")
        XCTAssertEqual(sent.value(forHTTPHeaderField: "content-type"), "application/x-www-form-urlencoded")
        XCTAssertEqual(sent.bodyData, body)
    }

    func testRedirectIsReturnedNotFollowed() async throws {
        StubURLProtocol.install { _ in .redirect(location: "https://evil.example.org/steal") }
        let client = URLSessionHTTPClient(session: StubURLProtocol.session())
        let response = try await client.send(HTTPRequest(method: .post, url: url, body: Data("secret=1".utf8)))
        XCTAssertEqual(response.statusCode, 302)
        XCTAssertEqual(response.header("location"), "https://evil.example.org/steal")
        // The negative half: nothing was sent to the redirect target.
        XCTAssertEqual(StubURLProtocol.requests.count, 1)
        XCTAssertEqual(StubURLProtocol.requests.first?.url, url)
    }

    func testTransportErrorMapsToRecoverableNetworkWithoutTheURL() async throws {
        StubURLProtocol.install { _ in .failure(.notConnectedToInternet) }
        let client = URLSessionHTTPClient(session: StubURLProtocol.session())
        do {
            _ = try await client.send(HTTPRequest(method: .get, url: url))
            XCTFail("expected a network error")
        } catch let OAuthError.recoverable(.network(detail, attempts, elapsedMillis)) {
            XCTAssertEqual(attempts, 1)
            XCTAssertGreaterThanOrEqual(elapsedMillis, 0)
            XCTAssertFalse(detail.contains("auth.example.com"))
            XCTAssertFalse(detail.contains("code=abc"))
            XCTAssertTrue(detail.contains("URLError"))
        }
    }

    func testURLsInAnErrorTextAreStripped() {
        let stripped = URLSessionHTTPClient.stripURLs("could not connect to https://auth.example.com/cb?code=abc now")
        XCTAssertEqual(stripped, "could not connect to <url> now")
    }

    func testCancelledCallerGetsCancellationNotNetworkError() async {
        StubURLProtocol.install { _ in .failure(.cancelled) }
        let client = URLSessionHTTPClient(session: StubURLProtocol.session())
        do {
            _ = try await client.send(HTTPRequest(method: .get, url: url))
            XCTFail("expected cancellation")
        } catch is CancellationError {
        } catch {
            XCTFail("expected CancellationError, got \(error)")
        }
    }
}
