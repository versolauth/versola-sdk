import CryptoKit
import Foundation
import os
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
/// Flutter mints no proof itself, but it has the authenticated client (`OAuthClient.httpClient()`,
/// `spec/oauth-sdk-api.md` section 10): the tests named `HttpRequest` below send the request the way
/// the Dart client does and the plugin runs it with `authenticatedSession`, so the call's own proof,
/// the resource's nonce challenge and the nonce loop are asserted through the bridge, on the wire and
/// at the resource server, with no token ever handed to Dart. Only the replay of a proof the SDK
/// sent needs the harness to reach the SDK's request and stays the native driver's. The
/// stolen-token requests are made with the token `accessToken()` hands over, which is what a
/// Flutter app holds and cannot present itself.
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

    func test33BridgeUserInfoUnderDpopCarriesTheDpopSchemeAndAProofBoundToTheToken() async throws {
        let bridge = try await bridge(clientId: Provider.dpopClientId, tokenBinding: .dpop(required: false))
        let metadata = try await bridge.native.metadata()
        try ok(await bridge.dart.login())
        let jkt = DpopResourceServer.thumbprint(try sdkKey().publicKey)
        let userinfoEndpoint = try XCTUnwrap(metadata.userinfoEndpoint)

        let subject = try self.subject(await bridge.dart.userInfo())

        let claimsMessage = try await bridge.dart.claims()
        XCTAssertEqual(subject, try XCTUnwrap(claimsMessage).subject)
        let sent = try XCTUnwrap(network.matching("GET", path(userinfoEndpoint)).first)
        XCTAssertEqual(sent.status, 200)
        let authorization = try XCTUnwrap(sent.header("Authorization"))
        XCTAssertTrue(authorization.hasPrefix("DPoP "), authorization)
        let claims = try XCTUnwrap(sent.proofClaims)
        XCTAssertEqual(claims["htm"] as? String, "GET")
        XCTAssertEqual(claims["htu"] as? String, userinfoEndpoint)
        XCTAssertEqual(claims["ath"] as? String, DpopResourceServer.sha256Url(String(authorization.dropFirst(5))))
        XCTAssertEqual(try self.jkt(of: sent.proofHeader), jkt)
    }

    func test33BridgeLogoutUnderDpopRevokesTheRefreshTokenAndTheProviderThenRefusesIt() async throws {
        let bridge = try await bridge(clientId: Provider.dpopClientId, tokenBinding: .dpop(required: false))
        let metadata = try await bridge.native.metadata()
        try ok(await bridge.dart.login())
        let sdkKey = try sdkKey()
        let refreshToken = try XCTUnwrap(network.matching("POST", path(metadata.tokenEndpoint)).first?.responseJSON?["refresh_token"] as? String)

        let outcome = try await bridge.dart.logout()

        let state = try await bridge.dart.sessionState()
        XCTAssertEqual(state, .unauthenticated)
        let revoke = try XCTUnwrap(network.matching("POST", path(try XCTUnwrap(metadata.revocationEndpoint))).first)
        XCTAssertNil(revoke.header("DPoP"))
        XCTAssertEqual(revoke.status, 200)
        XCTAssertTrue(outcome.tokenRevoked)
        var request = URLRequest(url: URL(string: metadata.tokenEndpoint)!)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.setValue(DpopResourceServer.forgeProof(sdkKey, method: "POST", url: metadata.tokenEndpoint, accessToken: nil), forHTTPHeaderField: "DPoP")
        request.httpBody = Data("grant_type=refresh_token&refresh_token=\(refreshToken)&client_id=\(Provider.dpopClientId)".utf8)
        let (data, response) = try await VirtualNetwork.session(record: false).data(for: request)
        XCTAssertEqual((response as? HTTPURLResponse)?.statusCode, 400, String(decoding: data, as: UTF8.self))
        XCTAssertTrue(String(decoding: data, as: UTF8.self).contains("invalid_grant"))
    }

    private static func nonceChallenge(_ nonce: String) -> VirtualNetwork.StubAnswer {
        VirtualNetwork.StubAnswer(
            status: 400, headers: ["Content-Type": "application/json", "DPoP-Nonce": nonce],
            body: Data(#"{"error":"use_dpop_nonce","error_description":"Authorization server requires nonce in DPoP proof"}"#.utf8)
        )
    }

    func test33BridgeANonceChallengeFromTheProvidersTokenEndpointIsRetriedOnceWithTheNonceAndTheLoginCompletes() async throws {
        let bridge = try await bridge(clientId: Provider.dpopClientId, tokenBinding: .dpop(required: false))
        let metadata = try await bridge.native.metadata()
        let tokenPath = path(metadata.tokenEndpoint)
        let challenges = OSAllocatedUnfairLock(initialState: 0)
        network.intercept { request -> VirtualNetwork.StubAnswer? in
            guard request.url?.path.hasSuffix(tokenPath) == true else { return nil }
            return challenges.withLock { count -> VirtualNetwork.StubAnswer? in count += 1; return count == 1 ? Self.nonceChallenge("provider-nonce-1") : nil }
        }

        try ok(await bridge.dart.login())

        let state = try await bridge.dart.sessionState()
        XCTAssertEqual(state, .authenticated)
        let requests = network.matching("POST", tokenPath)
        XCTAssertEqual(requests.count, 2, "exactly one retry: \(requests.map { "\($0.url) -> \($0.status)" })")
        guard requests.count == 2 else { return }
        XCTAssertEqual(requests[0].status, 400)
        XCTAssertNil(requests[0].proofClaims?["nonce"])
        XCTAssertEqual(requests[1].proofClaims?["nonce"] as? String, "provider-nonce-1")
        XCTAssertNotEqual(requests[0].proofClaims?["jti"] as? String, requests[1].proofClaims?["jti"] as? String)
        XCTAssertEqual(requests[1].status, 200)
    }

    func test33BridgeAProviderThatKeepsChallengingTheTokenRequestGetsOneRetryAndThenNonceLoop() async throws {
        let bridge = try await bridge(clientId: Provider.dpopClientId, tokenBinding: .dpop(required: false))
        let metadata = try await bridge.native.metadata()
        let tokenPath = path(metadata.tokenEndpoint)
        let issued = OSAllocatedUnfairLock(initialState: 0)
        network.intercept { request -> VirtualNetwork.StubAnswer? in
            guard request.url?.path.hasSuffix(tokenPath) == true else { return nil }
            return Self.nonceChallenge("provider-nonce-\(issued.withLock { count -> Int in count += 1; return count })")
        }

        let error = try failure(await bridge.dart.login())

        assertError(error, .recoverable, "nonceLoop")
        XCTAssertEqual(network.matching("POST", tokenPath).count, 2, "one request and one retry, no more")
        let state = try await bridge.dart.sessionState()
        XCTAssertNotEqual(state, .authenticated)
    }

    func test33BridgeACodeBoundToTheSdksKeyIsNotRedeemedWithAProofFromAnotherKey() async throws {
        let bridge = try await bridge(clientId: Provider.dpopClientId, tokenBinding: .dpop(required: false))
        let metadata = try await bridge.native.metadata()
        let tokenPath = path(metadata.tokenEndpoint)
        let attacker = P256.Signing.PrivateKey()
        let endpoint = metadata.tokenEndpoint
        network.rewriteRequest(tokenPath) { request in
            var forged = request
            forged.setValue(DpopResourceServer.forgeProof(attacker, method: "POST", url: endpoint, accessToken: nil), forHTTPHeaderField: "DPoP")
            return forged
        }

        let error = try failure(await bridge.dart.login())

        assertError(error, .configuration, "tokenRequestRejected")
        XCTAssertEqual(error.code, "invalid_request")
        XCTAssertTrue(error.errorDescription?.contains("dpop_jkt") == true, "\(String(describing: error.errorDescription))")
        let token = try XCTUnwrap(network.matching("POST", tokenPath).first)
        XCTAssertEqual(token.status, 400, token.responseBody ?? "")
        XCTAssertNil(token.responseJSON?["access_token"])
        let state = try await bridge.dart.sessionState()
        XCTAssertNotEqual(state, .authenticated)
    }

    func test33BridgeHttpRequestSendsTheDpopSchemeAndAProofBoundToTheTokenWhichTheResourceServerAccepts() async throws {
        let rs = try await DpopResourceServer.install(network, origin: Self.origin)
        let bridge = try await bridge(clientId: Provider.dpopClientId, protectedOrigins: [Self.origin], tokenBinding: .dpop(required: false))
        try ok(await bridge.dart.login())
        let jkt = DpopResourceServer.thumbprint(try sdkKey().publicKey)
        let claims = try await bridge.dart.claims()
        let subject = try XCTUnwrap(claims).subject

        let answer = try response(await bridge.dart.httpRequest(rs.url("/api/items?page=2")))

        XCTAssertEqual(answer.status, 200, String(decoding: answer.body.data, as: UTF8.self))
        let sent = try XCTUnwrap(network.transcript.first { $0.url.hasPrefix(Self.origin) })
        let authorization = try XCTUnwrap(sent.header("Authorization"))
        XCTAssertTrue(authorization.hasPrefix("DPoP "), authorization)
        let accessToken = String(authorization.dropFirst(5))
        let proof = try XCTUnwrap(sent.proofClaims)
        XCTAssertEqual(proof["htm"] as? String, "GET")
        XCTAssertEqual(proof["htu"] as? String, rs.url("/api/items"), "the URL without its query")
        XCTAssertEqual(proof["ath"] as? String, DpopResourceServer.sha256Url(accessToken))
        XCTAssertEqual(try self.jkt(of: sent.proofHeader), jkt)
        XCTAssertEqual((accessClaims(accessToken)["cnf"] as? [String: Any])?["jkt"] as? String, jkt)
        XCTAssertEqual(rs.attempts.map(\.verdict), [.accepted(jkt: jkt, subject: subject)])
        // The token itself never crossed: the app did not ask for it, and the response carries none.
        XCTAssertFalse(String(decoding: answer.body.data, as: UTF8.self).contains(accessToken))

        // An origin that is not protected gets neither the token nor a proof, whatever the app put in the headers.
        _ = try response(await bridge.dart.httpRequest(Provider.proxyOrigin + "/elsewhere", headers: [("DPoP", "app-own")]))
        let elsewhere = try XCTUnwrap(network.transcript.first { $0.url == Provider.proxyOrigin + "/elsewhere" })
        XCTAssertNil(elsewhere.header("Authorization"))
        XCTAssertEqual(elsewhere.header("DPoP"), "app-own")
    }

    func test33BridgeAnAuthorizationAndADpopHeaderTheAppSetOnTheDpopProtectedOriginAreReplacedTheResourceSeesExactlyOneOfEach() async throws {
        let rs = try await DpopResourceServer.install(network, origin: Self.origin)
        let bridge = try await bridge(clientId: Provider.dpopClientId, protectedOrigins: [Self.origin], tokenBinding: .dpop(required: false))
        try ok(await bridge.dart.login())

        let answer = try response(await bridge.dart.httpRequest(
            rs.url("/api"), headers: [("Authorization", "Bearer app-supplied"), ("DPoP", "app-forged"), ("dpop", "app-forged-too")]
        ))

        XCTAssertEqual(answer.status, 200, String(decoding: answer.body.data, as: UTF8.self))
        let sent = try XCTUnwrap(network.transcript.first { $0.url.hasPrefix(Self.origin) })
        XCTAssertTrue(try XCTUnwrap(sent.header("Authorization")).hasPrefix("DPoP "))
        XCTAssertFalse(try XCTUnwrap(sent.header("DPoP")).contains("app-forged"))
        XCTAssertEqual(rs.attempts.count, 1)
        guard case .accepted? = rs.attempts.first?.verdict else { return XCTFail("\(String(describing: rs.attempts.first?.verdict))") }
    }

    func test33BridgeHttpRequestAnswersTheResourcesNonceChallengeOnceWithTheNonceAndRemembersItForTheOrigin() async throws {
        let rs = try await DpopResourceServer.install(network, origin: Self.origin, nonce: "resource-nonce-1")
        let bridge = try await bridge(clientId: Provider.dpopClientId, protectedOrigins: [Self.origin], tokenBinding: .dpop(required: false))
        try ok(await bridge.dart.login())

        let first = try response(await bridge.dart.httpRequest(rs.url("/api")))

        XCTAssertEqual(first.status, 200)
        let sent = network.transcript.filter { $0.url.hasPrefix(Self.origin) }
        XCTAssertEqual(sent.count, 2, "exactly one retry: \(sent)")
        XCTAssertEqual(sent[0].status, 401)
        XCTAssertEqual(sent[0].responseHeader("DPoP-Nonce"), "resource-nonce-1")
        XCTAssertNil(sent[0].proofClaims?["nonce"])
        XCTAssertEqual(sent[1].proofClaims?["nonce"] as? String, "resource-nonce-1")
        XCTAssertNotEqual(sent[0].proofClaims?["jti"] as? String, sent[1].proofClaims?["jti"] as? String, "a fresh proof, not the first one resent")

        // The nonce is per origin and kept: the next call needs no challenge.
        _ = try response(await bridge.dart.httpRequest(rs.url("/api")))
        let afterwards = network.transcript.filter { $0.url.hasPrefix(Self.origin) }
        XCTAssertEqual(afterwards.count, 3)
        XCTAssertEqual(afterwards[2].proofClaims?["nonce"] as? String, "resource-nonce-1")
    }

    func test33BridgeAResourceThatKeepsChallengingGetsOneRetryAndThenNonceLoopThroughHttpRequest() async throws {
        let rs = try await DpopResourceServer.install(network, origin: Self.origin, nonce: "demanded", offered: "offered")
        let bridge = try await bridge(clientId: Provider.dpopClientId, protectedOrigins: [Self.origin], tokenBinding: .dpop(required: false))
        try ok(await bridge.dart.login())

        let error = try failure(await bridge.dart.httpRequest(rs.url("/api")))

        assertError(error, .recoverable, "nonceLoop")
        XCTAssertEqual(rs.attempts.count, 2, "one request and one retry, no more")
    }
}
