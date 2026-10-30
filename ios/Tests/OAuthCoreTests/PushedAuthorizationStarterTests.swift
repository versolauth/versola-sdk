import XCTest
@testable import OAuthCore

final class PushedAuthorizationStarterTests: XCTestCase {
    private let parEndpoint = "https://id.example.com/par"
    private let created = #"{"request_uri":"urn:ietf:params:oauth:request_uri:abc","expires_in":60}"#

    private func request() -> AuthorizationRequest {
        AuthorizationRequest.create(configuration: AuthzKit.configuration, scopes: ["openid"], dpopJkt: "jkt-1")
    }

    private func starter(_ http: RecordingHTTP, _ policy: PushedAuthorization) -> PushedAuthorizationStarter {
        PushedAuthorizationStarter(configuration: AuthzKit.configuration, httpClient: http, policy: policy)
    }

    private func assertStartFails(
        _ expected: OAuthError, policy: PushedAuthorization, metadata: ProviderMetadata,
        http: RecordingHTTP, file: StaticString = #filePath, line: UInt = #line
    ) async {
        do {
            _ = try await starter(http, policy).start(request: request(), metadata: metadata, now: AuthzKit.now)
            XCTFail("expected \(expected)", file: file, line: line)
        } catch {
            XCTAssertEqual(error as? OAuthError, expected, file: file, line: line)
        }
    }

    private let par = OAuthError.configuration(.providerUnsupported(capability: "par"))

    // MARK: Decision table

    func testWhenAdvertisedPushesAndOpensTheBrowserOnClientIdAndRequestUriOnly() async throws {
        let http = RecordingHTTP.json(201, created)
        let req = request()
        let started = try await starter(http, .whenAdvertised).start(
            request: req, metadata: AuthzKit.metadata(parEndpoint: parEndpoint), now: AuthzKit.now)

        let sent = await http.requests
        XCTAssertEqual(sent.count, 1)
        XCTAssertEqual(sent[0].method, .post)
        XCTAssertEqual(sent[0].url.absoluteString, parEndpoint)
        XCTAssertEqual(sent[0].headers["Content-Type"], "application/x-www-form-urlencoded")
        XCTAssertEqual(sent[0].headers["Accept"], "application/json")
        XCTAssertEqual(sent[0].body, FormEncoding.body(req.formParameters()))
        let form = String(decoding: sent[0].body ?? Data(), as: UTF8.self)
        XCTAssertTrue(form.contains("code_challenge="))
        XCTAssertTrue(form.contains("client_id=client-123"))
        XCTAssertTrue(form.contains("dpop_jkt=jkt-1"))

        let browser = AuthorizationResponseValidator.parseQuery(started.browserUri)
        XCTAssertEqual(Set(browser.keys), ["client_id", "request_uri"])
        XCTAssertEqual(browser["client_id"], "client-123")
        XCTAssertEqual(browser["request_uri"], "urn:ietf:params:oauth:request_uri:abc")
        XCTAssertTrue(started.browserUri.absoluteString.hasPrefix("https://id.example.com/authorize?client_id="))
        XCTAssertEqual(started.pending.state, req.state)
        XCTAssertEqual(started.pending.codeVerifier, req.codeVerifier.value)
    }

    func testTheBrowserUriLeaksNoRequestParameter() async throws {
        let http = RecordingHTTP.json(201, created)
        let started = try await starter(http, .whenAdvertised).start(
            request: request(), metadata: AuthzKit.metadata(parEndpoint: parEndpoint), now: AuthzKit.now)
        let text = started.browserUri.absoluteString
        for leaked in ["state=", "nonce=", "code_challenge", "redirect_uri", "scope=", "dpop_jkt"] {
            XCTAssertFalse(text.contains(leaked), "\(leaked) in \(text)")
        }
    }

    func testWhenAdvertisedWithoutAnEndpointIsThePlainRequestAndNeverTouchesTheNetwork() async throws {
        let http = RecordingHTTP.json(500, "")
        let req = request()
        let started = try await starter(http, .whenAdvertised).start(
            request: req, metadata: AuthzKit.metadata(), now: AuthzKit.now)
        let count = await http.requests.count
        XCTAssertEqual(count, 0)
        let query = AuthorizationResponseValidator.parseQuery(started.browserUri)
        XCTAssertEqual(query["state"], req.state)
        XCTAssertEqual(query["code_challenge"], req.codeVerifier.challengeS256())
        XCTAssertNil(query["request_uri"])
    }

    func testNeverIsPlainEvenWhenAnEndpointIsAdvertised() async throws {
        let http = RecordingHTTP.json(201, created)
        let started = try await starter(http, .never).start(
            request: request(), metadata: AuthzKit.metadata(parEndpoint: parEndpoint), now: AuthzKit.now)
        let count = await http.requests.count
        XCTAssertEqual(count, 0)
        XCTAssertNotNil(AuthorizationResponseValidator.parseQuery(started.browserUri)["code_challenge"])
    }

    func testNeverWithARequiredProviderIsProviderUnsupportedRatherThanARefusedRequest() async {
        let http = RecordingHTTP.json(201, created)
        await assertStartFails(par, policy: .never,
                               metadata: AuthzKit.metadata(parEndpoint: parEndpoint, requirePar: true), http: http)
        let count = await http.requests.count
        XCTAssertEqual(count, 0)
    }

    func testAProviderRequiringParWithNowhereToPushToIsUnsupportedWhateverThePolicy() async {
        let http = RecordingHTTP.json(201, created)
        await assertStartFails(par, policy: .whenAdvertised, metadata: AuthzKit.metadata(requirePar: true), http: http)
        await assertStartFails(par, policy: .never, metadata: AuthzKit.metadata(requirePar: true), http: http)
    }

    func testRequiredWithoutAnEndpointIsProviderUnsupported() async {
        let http = RecordingHTTP.json(201, created)
        await assertStartFails(par, policy: .required, metadata: AuthzKit.metadata(), http: http)
        let count = await http.requests.count
        XCTAssertEqual(count, 0)
    }

    func testRequiredWithAnEndpointPushes() async throws {
        let http = RecordingHTTP.json(201, created)
        let started = try await starter(http, .required).start(
            request: request(), metadata: AuthzKit.metadata(parEndpoint: parEndpoint), now: AuthzKit.now)
        XCTAssertEqual(AuthorizationResponseValidator.parseQuery(started.browserUri)["request_uri"],
                       "urn:ietf:params:oauth:request_uri:abc")
    }

    func testThePendingRequestRecordsWhetherIssIsRequiredAndWhen() async throws {
        let http = RecordingHTTP.json(201, created)
        let started = try await starter(http, .whenAdvertised).start(
            request: request(), metadata: AuthzKit.metadata(issSupported: true, parEndpoint: parEndpoint),
            now: AuthzKit.now)
        XCTAssertTrue(started.pending.issRequired)
        XCTAssertEqual(started.pending.createdAt, AuthzKit.now)
        XCTAssertEqual(started.pending.extensions, [:])
    }

    // MARK: PAR answers

    func testAnOkStatusIsAcceptedLikeCreated() async throws {
        let http = RecordingHTTP.json(200, created)
        _ = try await starter(http, .required).start(
            request: request(), metadata: AuthzKit.metadata(parEndpoint: parEndpoint), now: AuthzKit.now)
    }

    func testAnOauthErrorBodyOn400401And403IsAuthorizationRejected() async {
        let cases: [(Int, String, String?)] = [
            (400, #"{"error":"invalid_request","error_description":"redirect_uri mismatch"}"#, "redirect_uri mismatch"),
            (401, #"{"error":"invalid_client"}"#, nil),
            (403, #"{"error":"unauthorized_client","error_description":"not allowed"}"#, "not allowed"),
        ]
        for (status, body, description) in cases {
            let code = body.contains("invalid_request") ? "invalid_request"
                : body.contains("invalid_client") ? "invalid_client" : "unauthorized_client"
            await assertStartFails(
                .configuration(.authorizationRejected(code: code, description: description)),
                policy: .required, metadata: AuthzKit.metadata(parEndpoint: parEndpoint),
                http: RecordingHTTP.json(status, body))
        }
    }

    func testA400WithoutAnOauthErrorIsAnInvalidConfigurationNamingTheStatus() async {
        await assertStartFails(.configuration(.invalidConfiguration(detail: "PAR endpoint answered 400")),
                               policy: .required, metadata: AuthzKit.metadata(parEndpoint: parEndpoint),
                               http: RecordingHTTP.json(400, "<html>bad</html>"))
        await assertStartFails(.configuration(.invalidConfiguration(detail: "PAR endpoint answered 404")),
                               policy: .required, metadata: AuthzKit.metadata(parEndpoint: parEndpoint),
                               http: RecordingHTTP.json(404, ""))
    }

    func testAnEmptyErrorCodeIsNotTakenAsARejection() async {
        await assertStartFails(.configuration(.invalidConfiguration(detail: "PAR endpoint answered 400")),
                               policy: .required, metadata: AuthzKit.metadata(parEndpoint: parEndpoint),
                               http: RecordingHTTP.json(400, #"{"error":""}"#))
    }

    func testAServerSideFailureIsRecoverableServerWithItsStatus() async {
        for status in [500, 503, 408, 429] {
            await assertStartFails(
                .recoverable(.server(status: status, retryAfterMillis: nil, attempts: 1, elapsedMillis: 0)),
                policy: .required, metadata: AuthzKit.metadata(parEndpoint: parEndpoint),
                http: RecordingHTTP.json(status, ""))
        }
    }

    func testATransportFailureIsRecoverableNetwork() async {
        let http = RecordingHTTP { _ in throw TransportFailure() }
        do {
            _ = try await starter(http, .required).start(
                request: request(), metadata: AuthzKit.metadata(parEndpoint: parEndpoint), now: AuthzKit.now)
            XCTFail("expected a failure")
        } catch OAuthError.recoverable(.network) {
        } catch {
            XCTFail("unexpected \(error)")
        }
    }

    func testASuccessBodyWithoutRequestUriOrAPositiveLifetimeIsRefused() async {
        let bodies = [#"{"expires_in":60}"#, #"{"request_uri":"","expires_in":60}"#,
                      #"{"request_uri":"urn:x"}"#, #"{"request_uri":"urn:x","expires_in":0}"#,
                      #"{"request_uri":"urn:x","expires_in":-5}"#, "not json"]
        for body in bodies {
            do {
                _ = try await starter(RecordingHTTP.json(201, body), .required).start(
                    request: request(), metadata: AuthzKit.metadata(parEndpoint: parEndpoint), now: AuthzKit.now)
                XCTFail("accepted \(body)")
            } catch OAuthError.configuration(.invalidConfiguration) {
            } catch {
                XCTFail("unexpected \(error) for \(body)")
            }
        }
    }

    func testAnEndpointThatIsNotAUrlIsAConfigurationFault() async {
        do {
            _ = try await starter(RecordingHTTP.json(201, created), .required).start(
                request: request(), metadata: AuthzKit.metadata(parEndpoint: "not a url"), now: AuthzKit.now)
            XCTFail("expected a failure")
        } catch OAuthError.configuration(.discoveryMalformed) {
            // The endpoint is checked where it is used, before the URL is built: the same
            // Configuration category, naming the document as the culprit.
        } catch {
            XCTFail("unexpected \(error)")
        }
    }

    func testTheStarterDoesNotBindTheDpopKeyItself() {
        XCTAssertFalse(starter(RecordingHTTP.json(201, created), .whenAdvertised).bindsDpopKeyItself)
    }
}
