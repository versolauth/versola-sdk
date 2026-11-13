import Foundation
import XCTest
@testable import OAuthCore
@testable import VersolaEdge

final class EdgeStarterTests: XCTestCase {
    private let configuration = CoreConfiguration(
        issuer: "https://auth.example.com", clientId: "mobile-app", redirectUri: URL(string: "https://app.example.com/oauth")!
    )
    private let edge = URL(string: "https://edge.example.com/")!
    private static let started = """
    {"client_id":"mobile-app","request_uri":"urn:par:abc","expires_in":60,"authorization_endpoint":"https://auth.example.com/authorize",\
    "state":"st","blob":"bl","token_endpoint":"https://auth.example.com:8443/token","revocation_endpoint":"https://auth.example.com:8443/revoke"}
    """

    private func request() throws -> AuthorizationRequest {
        try AuthorizationRequest(
            configuration: configuration, scopes: ["openid", "profile"], state: "ignored", nonce: "n-1",
            codeVerifier: CodeVerifier(value: String(repeating: "v", count: 43)), acrValues: [], maxAge: nil, dpopJkt: nil, parameters: .none
        )
    }

    private let metadata = ProviderMetadata(
        issuer: "https://auth.example.com", authorizationEndpoint: "https://auth.example.com/authorize",
        tokenEndpoint: "https://auth.example.com/token"
    )

    private func starter(_ http: HTTPClient, _ dpop: DpopProofSource, _ evidence: (any NativeStartAttestation)? = nil) throws -> EdgeAuthorizationStarter {
        try EdgeAuthorizationStarter(configuration: configuration, edgeBaseUrl: edge, httpClient: http, dpop: dpop, attestation: evidence)
    }

    func testStartsThroughEdgeAndKeepsTheBlobInsteadOfAVerifier() async throws {
        let http = RecordingHTTP([json(200, Self.started)])
        let result = try await starter(http, ProofSource()).start(request: try request(), metadata: metadata, now: Date(timeIntervalSince1970: 1000))
        let sent = await http.requests[0]
        XCTAssertEqual(sent.url.absoluteString, "https://edge.example.com/native/start/mobile-app")
        XCTAssertEqual(sent.headers["DPoP"]?.hasPrefix("e30."), true)
        XCTAssertEqual(formFields(sent)["scope"], "openid profile")
        XCTAssertNil(formFields(sent)["attestation_platform"])
        XCTAssertEqual(result.pending.state, "st")
        XCTAssertEqual(result.pending.codeVerifier, "")
        XCTAssertTrue(result.pending.issRequired)
        XCTAssertEqual(result.pending.extensions[EdgeExtension.blob], "bl")
        XCTAssertEqual(result.browserUri.absoluteString, "https://auth.example.com/authorize?client_id=mobile-app&request_uri=urn%3Apar%3Aabc")
        XCTAssertEqual(result.expiresAt, Date(timeIntervalSince1970: 1060))
    }

    func testEvidenceIsBoundToTheJtiOfTheProofOnTheSameRequest() async throws {
        let http = RecordingHTTP([json(200, Self.started)])
        let evidence = FakeEvidence()
        _ = try await starter(http, ProofSource(), evidence).start(request: try request(), metadata: metadata, now: Date())
        let asked = await evidence.asked
        XCTAssertEqual(asked.count, 1)
        XCTAssertEqual(asked[0].jti, "jti-1")
        XCTAssertEqual(asked[0].jkt, "jkt")
        XCTAssertEqual(asked[0].clientId, "mobile-app")
        let fields = formFields(await http.requests[0])
        XCTAssertEqual(fields["attestation_platform"], "ios")
        XCTAssertEqual(fields["attestation_key_id"], "key")
        // base64 has '+', '/' and '=': they arrive intact only if the body was percent-encoded.
        XCTAssertEqual(fields["attestation_object"], "+/8=")
    }

    func testANonceChallengeRetriesWithFreshEvidenceAndForgetsTheAttestationThatWasNotSeen() async throws {
        let http = RecordingHTTP([
            json(401, "", headers: ["WWW-Authenticate": "DPoP error=\"use_dpop_nonce\"", "DPoP-Nonce": "n1"]),
            json(200, Self.started),
        ])
        let proofs = ProofSource()
        let evidence = FakeEvidence()
        _ = try await starter(http, proofs, evidence).start(request: try request(), metadata: metadata, now: Date())
        let asked = await evidence.asked
        XCTAssertEqual(asked.map(\.jti), ["jti-1", "jti-2"])
        let value1 = await evidence.notAccepted
        XCTAssertEqual(value1, 1)
        let sent = await http.requests
        XCTAssertNotNil(formFields(sent[1])["attestation_object"], "the key is attested again, not asserted")
        let value2 = await proofs.minted[1].nonce
        XCTAssertEqual(value2, "n1")
    }

    func testASecondNonceChallengeIsALoop() async throws {
        let challenge = json(401, "", headers: ["WWW-Authenticate": "DPoP error=\"use_dpop_nonce\"", "DPoP-Nonce": "n1"])
        let http = RecordingHTTP([challenge, challenge])
        do {
            _ = try await starter(http, ProofSource()).start(request: try request(), metadata: metadata, now: Date())
            XCTFail("no error")
        } catch OAuthError.recoverable(.nonceLoop) {}
    }

    func testAnUnanswerableChallengeStillForgetsTheAttestationThatWasNotSeen() async throws {
        let http = RecordingHTTP([json(401, "", headers: ["WWW-Authenticate": "DPoP error=\"use_dpop_nonce\""])])
        let evidence = FakeEvidence()
        do {
            _ = try await starter(http, ProofSource(), evidence).start(request: try request(), metadata: metadata, now: Date())
            XCTFail("no error")
        } catch OAuthError.recoverable(.nonceLoop) {}
        let notAccepted = await evidence.notAccepted
        XCTAssertEqual(notAccepted, 1)
    }

    func testAKeyEdgeNeverSawAttestedIsForgottenAndTheRefusalIsReported() async throws {
        let http = RecordingHTTP([json(400, #"{"error":"invalid_client_attestation","error_description":"this key has not been attested: send the attestation object"}"#)])
        let evidence = FakeEvidence()
        do {
            _ = try await starter(http, ProofSource(), evidence).start(request: try request(), metadata: metadata, now: Date())
            XCTFail("no error")
        } catch OAuthError.configuration(.authorizationRejected(let code, _)) {
            XCTAssertEqual(code, "invalid_client_attestation")
        }
        let value3 = await evidence.notAccepted
        XCTAssertEqual(value3, 1)
    }

    func testAnyOtherAttestationRefusalKeepsTheKey() async throws {
        let http = RecordingHTTP([json(400, #"{"error":"invalid_client_attestation","error_description":"the app is not one this client accepts"}"#)])
        let evidence = FakeEvidence()
        do {
            _ = try await starter(http, ProofSource(), evidence).start(request: try request(), metadata: metadata, now: Date())
            XCTFail("no error")
        } catch OAuthError.configuration(.authorizationRejected) {}
        let value4 = await evidence.notAccepted
        XCTAssertEqual(value4, 0)
    }

    func testAnUnknownClientAndAServerFaultAreNamed() async throws {
        do {
            _ = try await starter(RecordingHTTP([json(404, "")]), ProofSource()).start(request: try request(), metadata: metadata, now: Date())
            XCTFail("no error")
        } catch OAuthError.configuration(.invalidConfiguration(let detail)) {
            XCTAssertTrue(detail.contains("mobile-app"))
        }
        do {
            _ = try await starter(RecordingHTTP([json(503, "")]), ProofSource()).start(request: try request(), metadata: metadata, now: Date())
            XCTFail("no error")
        } catch OAuthError.recoverable(.server) {}
    }

    func testAResponseWithoutABlobIsRefused() async throws {
        let http = RecordingHTTP([json(200, #"{"request_uri":"u","state":"s","token_endpoint":"https://a/t","revocation_endpoint":"https://a/r"}"#)])
        do {
            _ = try await starter(http, ProofSource()).start(request: try request(), metadata: metadata, now: Date())
            XCTFail("no error")
        } catch OAuthError.configuration(.tokenResponseMalformed) {}
    }

    func testARedirectUriThatIsNotHttpsIsRefusedAtConstruction() {
        let custom = CoreConfiguration(issuer: "https://auth.example.com", clientId: "c", redirectUri: URL(string: "app://cb")!)
        XCTAssertThrowsError(try EdgeAuthorizationStarter(configuration: custom, edgeBaseUrl: edge, httpClient: RecordingHTTP([]), dpop: ProofSource()))
    }
}
