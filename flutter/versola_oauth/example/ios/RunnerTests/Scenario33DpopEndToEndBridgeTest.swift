import CryptoKit
import Foundation
import XCTest
@testable import OAuthClient
@testable import OAuthCore
@testable import versola_oauth

/// `33-dpop-end-to-end` through the bridge: the plugin's `TokenBindingMessage.dpop` /
/// `dpopRequireHardware` against a provider that requires DPoP and a resource server that verifies
/// it. The assertions are the native driver's (`Scenario33DpopEndToEndTest`); the key is the SDK's
/// own `SecureEnclaveDpopKey` told no Secure Enclave exists, so the tier is **software** and nothing
/// here says anything about the Secure Enclave.
///
/// Flutter has no authenticated client and mints no proof (`spec/oauth-sdk-api.md` section 10), so
/// what a native test proved through the authenticated session (the call's own proof, the resource's
/// nonce challenge, the replay of a proof the SDK sent) is the native facades'. The bridge makes the
/// stolen-token requests with the token `accessToken()` hands over, which is what a Flutter app
/// holds and cannot present itself.
final class Scenario33DpopEndToEndBridgeTest: BridgeConformance {
    private static let origin = "http://localhost:18083"

    override func setUp() async throws {
        try await super.setUp()
        let (discovery, _) = try await URLSession.shared.data(from: URL(string: provider.issuer + "/.well-known/openid-configuration")!)
        let object = (try? JSONSerialization.jsonObject(with: discovery)) as? [String: Any]
        let algorithms = object?["dpop_signing_alg_values_supported"] as? [String] ?? []
        guard algorithms.contains("ES256") else {
            throw XCTSkip("\(provider.name) does not advertise dpop_signing_alg_values_supported with ES256 (spec/providers.md), so DPoP is not driven")
        }
    }

    private func sdkKey() throws -> P256.Signing.PrivateKey { try XCTUnwrap(dpopKeyStore.softwareKey, "the SDK generated no software DPoP key") }

    private func accessClaims(_ token: String) -> [String: Any] { DpopResourceServer.decode(token.split(separator: ".")[1].description) ?? [:] }

    private func jkt(of proof: [String: Any]?) throws -> String {
        let jwk = try XCTUnwrap(proof?["jwk"] as? [String: Any])
        return DpopResourceServer.thumbprint(x: try XCTUnwrap(jwk["x"] as? String), y: try XCTUnwrap(jwk["y"] as? String))
    }

    func test33BridgeTheTokenRequestCarriesAValidProofAndTheIssuedTokenIsDpopBoundToTheSdksKey() async throws {
        let bridge = try await bridge(clientId: Provider.dpopClientId, tokenBinding: .dpop(required: false))
        let metadata = try await bridge.native.metadata()

        try ok(await bridge.dart.login())

        let state = try await bridge.dart.sessionState()
        XCTAssertEqual(state, .authenticated)
        // The tier is read back through the bridge, not assumed (security.md).
        let attestation = try await bridge.dart.keyAttestation()
        XCTAssertEqual((attestation as? KeyAttestationOk)?.tier, "software", "\(attestation)")
        XCTAssertTrue(logger.warnings.contains { $0.contains("software-backed") }, "\(logger.warnings)")
        let jkt = DpopResourceServer.thumbprint(try sdkKey().publicKey)

        let authorization: [String: String]
        if let par = metadata.pushedAuthorizationRequestEndpoint {
            authorization = try theRequest("POST", path(par)).form.compactMapValues(\.first)
        } else {
            authorization = query(try XCTUnwrap(browser.opened.first))
        }
        XCTAssertEqual(authorization["dpop_jkt"], jkt)

        let token = try theRequest("POST", path(metadata.tokenEndpoint))
        let header = try XCTUnwrap(token.proofHeader)
        let claims = try XCTUnwrap(token.proofClaims)
        XCTAssertEqual(header["typ"] as? String, "dpop+jwt")
        XCTAssertEqual(header["alg"] as? String, "ES256")
        XCTAssertEqual(Set((header["jwk"] as? [String: Any] ?? [:]).keys), ["kty", "crv", "x", "y"])
        XCTAssertEqual(try self.jkt(of: header), jkt)
        XCTAssertEqual(claims["htm"] as? String, "POST")
        XCTAssertEqual(claims["htu"] as? String, metadata.tokenEndpoint)
        XCTAssertNil(claims["ath"])
        assertNoSecretOnTheWire(token)

        XCTAssertEqual(token.responseJSON?["token_type"] as? String, "DPoP")
        let accessToken = try XCTUnwrap(token.responseJSON?["access_token"] as? String)
        XCTAssertEqual((accessClaims(accessToken)["cnf"] as? [String: Any])?["jkt"] as? String, jkt)
        // What a Flutter app is handed: the token and its type, which it has no way to present.
        let handedOver = try self.token(await bridge.dart.accessToken())
        XCTAssertEqual(handedOver.value, accessToken)
        XCTAssertEqual(handedOver.tokenType, "DPoP")
    }

    func test33BridgeARefreshKeepsTheKeyAndTheNewTokenIsBoundToIt() async throws {
        let bridge = try await bridge(clientId: Provider.dpopClientId, tokenBinding: .dpop(required: false))
        let metadata = try await bridge.native.metadata()
        try ok(await bridge.dart.login())
        let jkt = DpopResourceServer.thumbprint(try sdkKey().publicKey)
        let before = try token(await bridge.dart.accessToken()).value

        try ok(await bridge.dart.refresh())

        let requests = network.matching("POST", path(metadata.tokenEndpoint))
        XCTAssertEqual(requests.count, 2)
        let login = requests[0], refresh = requests[1]
        XCTAssertEqual(refresh.field("grant_type"), "refresh_token")
        XCTAssertEqual(login.proofHeader?["jwk"] as? [String: String], refresh.proofHeader?["jwk"] as? [String: String])
        XCTAssertEqual(try self.jkt(of: refresh.proofHeader), jkt)
        XCTAssertEqual(refresh.proofClaims?["htm"] as? String, "POST")
        XCTAssertEqual(refresh.proofClaims?["htu"] as? String, metadata.tokenEndpoint)
        XCTAssertNotEqual(login.proofClaims?["jti"] as? String, refresh.proofClaims?["jti"] as? String)
        XCTAssertNil(refresh.proofClaims?["ath"])

        XCTAssertEqual(refresh.responseJSON?["token_type"] as? String, "DPoP")
        let after = try XCTUnwrap(refresh.responseJSON?["access_token"] as? String)
        XCTAssertNotEqual(before, after)
        XCTAssertEqual((accessClaims(after)["cnf"] as? [String: Any])?["jkt"] as? String, jkt)
        let current = try token(await bridge.dart.accessToken()).value
        XCTAssertEqual(after, current)
    }

    func test33BridgeAStolenAccessTokenIsRefusedWithoutTheKeyWithAnotherKeyAndWithAProofThatDoesNotMatch() async throws {
        let rs = try await DpopResourceServer.install(network, origin: Self.origin)
        let bridge = try await bridge(clientId: Provider.dpopClientId, protectedOrigins: [Self.origin], tokenBinding: .dpop(required: false))
        try ok(await bridge.dart.login())
        let accessToken = try token(await bridge.dart.accessToken())
        XCTAssertEqual(accessToken.tokenType, "DPoP")

        try await rs.assertStolenTokenIsRefused(token: accessToken.value, sdkKey: try sdkKey())
    }

    func test33BridgeRequireHardwareOnAHostThatProducesASoftwareKeyIsRefusedWithHardwareBindingUnavailableBeforeAnyAuthorizationRequest() async throws {
        let bridge = try await bridge(clientId: Provider.dpopClientId, tokenBinding: .dpop(required: true))
        let metadata = try await bridge.native.metadata()

        let error = try failure(await bridge.dart.login())

        assertError(error, .configuration, "hardwareBindingUnavailable")
        XCTAssertTrue(browser.opened.isEmpty, "\(browser.opened)")
        let forbidden = [metadata.tokenEndpoint, metadata.authorizationEndpoint, metadata.pushedAuthorizationRequestEndpoint].compactMap { $0 }.map(path)
        XCTAssertTrue(network.transcript.allSatisfy { entry in !forbidden.contains { entry.path.hasSuffix($0) } }, "\(network.transcript.map { "\($0.method) \($0.url)" })")
        let state = try await bridge.dart.sessionState()
        XCTAssertEqual(state, .unauthenticated)
        // Asking for the tier is refused the same way: asking generates the key (flutter.md).
        let attestation = try await bridge.dart.keyAttestation()
        let refused = try XCTUnwrap(attestation as? KeyAttestationFailure, "\(attestation)")
        XCTAssertEqual(refused.error.kind, "hardwareBindingUnavailable")
    }

    func test33BridgeAClientTheProviderRequiresDpopForGetsNoTokenFromAClientConfiguredForBearer() async throws {
        let bridge = try await bridge(clientId: Provider.dpopClientId, tokenBinding: .bearer)
        let metadata = try await bridge.native.metadata()

        _ = try failure(await bridge.dart.login())

        let token = try XCTUnwrap(network.matching("POST", path(metadata.tokenEndpoint)).first)
        XCTAssertNil(token.header("DPoP"))
        XCTAssertEqual(token.status, 400, token.responseBody ?? "")
        XCTAssertNil(token.responseJSON?["access_token"])
        let state = try await bridge.dart.sessionState()
        XCTAssertNotEqual(state, .authenticated)
    }

    func test33BridgeTheProviderBindsTheRefreshTokenToTheKeyAsWellSoWithoutTheKeyItBuysNothing() async throws {
        let bridge = try await bridge(clientId: Provider.dpopClientId, tokenBinding: .dpop(required: false))
        let metadata = try await bridge.native.metadata()
        try ok(await bridge.dart.login())
        let refreshToken = try XCTUnwrap(network.matching("POST", path(metadata.tokenEndpoint)).first?.responseJSON?["refresh_token"] as? String)
        let attacker = P256.Signing.PrivateKey()

        func refresh(_ proof: String?) async throws -> Int {
            var request = URLRequest(url: URL(string: metadata.tokenEndpoint)!)
            request.httpMethod = "POST"
            request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
            if let proof { request.setValue(proof, forHTTPHeaderField: "DPoP") }
            request.httpBody = Data("grant_type=refresh_token&refresh_token=\(refreshToken)&client_id=\(Provider.dpopClientId)".utf8)
            let (_, response) = try await VirtualNetwork.session(record: false).data(for: request)
            return (response as? HTTPURLResponse)?.statusCode ?? -1
        }

        let noProof = try await refresh(nil)
        let otherKey = try await refresh(DpopResourceServer.forgeProof(attacker, method: "POST", url: metadata.tokenEndpoint, accessToken: nil))
        XCTAssertEqual(noProof, 400)
        XCTAssertEqual(otherKey, 400)

        // Refused attempts did not spend it: the SDK, which holds the key, still refreshes.
        try ok(await bridge.dart.refresh())
        let state = try await bridge.dart.sessionState()
        XCTAssertEqual(state, .authenticated)
    }
}
