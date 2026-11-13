import Foundation
import XCTest
@testable import OAuthCore
@testable import VersolaEdge

final class EdgeTokenClientTests: XCTestCase {
    private let configuration = CoreConfiguration(
        issuer: "https://auth.example.com", clientId: "mobile-app", redirectUri: URL(string: "https://app.example.com/oauth")!
    )
    private let edge = URL(string: "https://edge.example.com")!
    private let issued = #"{"access_token":"at","token_type":"DPoP","expires_in":300,"refresh_token":"rt"}"#
    private let tokenEndpoint = "https://auth.example.com:8443/token"

    private func client(_ http: HTTPClient, _ dpop: DpopProofSource, _ store: any EdgeEndpointsStore = InMemoryEdgeEndpointsStore()) throws -> EdgeNativeTokenClient {
        let document = ProviderMetadata(issuer: "https://auth.example.com", authorizationEndpoint: "https://auth.example.com/authorize", tokenEndpoint: "https://auth.example.com/token")
        return try EdgeNativeTokenClient(configuration: configuration, edgeBaseUrl: edge, httpClient: http, dpop: dpop, metadata: { document }, endpoints: store)
    }

    private func grant(_ extensions: [String: String]? = nil) -> AuthorizationGrant {
        AuthorizationGrant(
            code: "code-1", codeVerifier: "", redirectUri: "https://app.example.com/oauth",
            extensions: extensions ?? [EdgeExtension.blob: "bl", EdgeExtension.tokenEndpoint: tokenEndpoint, EdgeExtension.revocationEndpoint: "https://auth.example.com:8443/revoke"],
            nonce: "n", state: "st", iss: "https://auth.example.com"
        )
    }

    func testCompleteSendsTheBlobAndSignsTheProofForAuthsOwnEndpoint() async throws {
        let http = RecordingHTTP([json(200, issued)])
        let proofs = ProofSource()
        let store = InMemoryEdgeEndpointsStore()
        let token = try await client(http, proofs, store).exchange(grant())
        XCTAssertEqual(token.accessToken, "at")
        let sent = await http.requests[0]
        XCTAssertEqual(sent.url.absoluteString, "https://edge.example.com/native/complete/mobile-app")
        XCTAssertEqual(formFields(sent)["blob"], "bl")
        XCTAssertEqual(formFields(sent)["iss"], "https://auth.example.com")
        XCTAssertNil(formFields(sent)["code_verifier"])
        let value1 = await proofs.minted[0].url.absoluteString
        XCTAssertEqual(value1, tokenEndpoint)
        let saved = try await store.load()
        XCTAssertEqual(saved, EdgeNativeEndpoints(tokenEndpoint: tokenEndpoint, revocationEndpoint: "https://auth.example.com:8443/revoke"))
    }

    func testAGrantNotStartedThroughEdgeIsRefusedBeforeAnythingIsSent() async throws {
        let http = RecordingHTTP([json(200, issued)])
        do {
            _ = try await client(http, ProofSource()).exchange(grant([:]))
            XCTFail("no error")
        } catch OAuthError.configuration(.invalidConfiguration) {}
        let value2 = await http.requests.isEmpty
        XCTAssertTrue(value2)
    }

    func testARefreshSignsForTheRememberedEndpointAndForwardsTheIdempotencyKey() async throws {
        let http = RecordingHTTP([json(200, issued)])
        let proofs = ProofSource()
        let store = InMemoryEdgeEndpointsStore(EdgeNativeEndpoints(tokenEndpoint: tokenEndpoint, revocationEndpoint: "https://auth.example.com:8443/revoke"))
        _ = try await client(http, proofs, store).refresh(refreshToken: "rt-0", idempotencyKey: "idem-1")
        let sent = await http.requests[0]
        XCTAssertEqual(sent.url.absoluteString, "https://edge.example.com/native/token/mobile-app")
        XCTAssertEqual(sent.headers["Idempotency-Key"], "idem-1")
        XCTAssertEqual(formFields(sent)["refresh_token"], "rt-0")
        let value3 = await proofs.minted[0].url.absoluteString
        XCTAssertEqual(value3, tokenEndpoint)
    }

    func testARefreshWithNothingRememberedFallsBackToDiscovery() async throws {
        let http = RecordingHTTP([json(200, issued)])
        let proofs = ProofSource()
        _ = try await client(http, proofs).refresh(refreshToken: "rt-0", idempotencyKey: "idem-1")
        let value4 = await proofs.minted[0].url.absoluteString
        XCTAssertEqual(value4, "https://auth.example.com/token")
    }

    func testABearerTokenIsRefused() async throws {
        let http = RecordingHTTP([json(200, #"{"access_token":"at","token_type":"Bearer","expires_in":300}"#)])
        do {
            _ = try await client(http, ProofSource()).exchange(grant())
            XCTFail("no error")
        } catch OAuthError.configuration(.hardwareBindingUnavailable) {}
    }

    func testRevokeSignsForTheRevocationEndpointAndAnswersANonceChallengeOnce() async throws {
        let http = RecordingHTTP([
            json(401, "", headers: ["WWW-Authenticate": "DPoP error=\"use_dpop_nonce\"", "DPoP-Nonce": "n1"]),
            json(200, ""),
        ])
        let proofs = ProofSource()
        let store = InMemoryEdgeEndpointsStore(EdgeNativeEndpoints(tokenEndpoint: tokenEndpoint, revocationEndpoint: "https://auth.example.com:8443/revoke"))
        try await client(http, proofs, store).revoke(refreshToken: "rt-0")
        let sent = await http.requests
        XCTAssertEqual(sent.count, 2)
        XCTAssertEqual(sent[0].url.absoluteString, "https://edge.example.com/native/revoke/mobile-app")
        XCTAssertEqual(formFields(sent[0])["token"], "rt-0")
        let minted = await proofs.minted
        XCTAssertEqual(minted[0].url.absoluteString, "https://auth.example.com:8443/revoke")
        XCTAssertEqual(minted[1].nonce, "n1")
    }

    func testAnUnknownClientIsNamedAtTheTokenEndpoint() async throws {
        do {
            _ = try await client(RecordingHTTP([json(404, "")]), ProofSource()).refresh(refreshToken: "rt", idempotencyKey: "i")
            XCTFail("no error")
        } catch OAuthError.configuration(.invalidConfiguration(let detail)) {
            XCTAssertTrue(detail.contains("mobile-app"))
        }
    }

    func testTheFileStoreRoundTripsAndDropsADamagedFile() async throws {
        let file = FileManager.default.temporaryDirectory.appendingPathComponent("edge-\(UUID().uuidString)/endpoints.json")
        let store = FileEdgeEndpointsStore(file: file)
        let value = EdgeNativeEndpoints(tokenEndpoint: "https://a/t", revocationEndpoint: "https://a/r")
        try await store.save(value)
        let loaded = try await store.load()
        XCTAssertEqual(loaded, value)
        try Data("{".utf8).write(to: file)
        let damaged = try await store.load()
        XCTAssertNil(damaged)
        XCTAssertFalse(FileManager.default.fileExists(atPath: file.path))
    }
}
