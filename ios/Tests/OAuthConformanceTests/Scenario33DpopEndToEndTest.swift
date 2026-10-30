import CryptoKit
import Foundation
import XCTest
@testable import OAuthClient
@testable import OAuthCore

/// `33-dpop-end-to-end`: DPoP (RFC 9449) proven against a provider that requires it and a
/// resource server that verifies it, observed on the wire. The key is the SDK's own
/// `SecureEnclaveDpopKey` told no Secure Enclave exists (`ProviderConformance.client`), so the
/// tier this run proves is **software**; the Secure Enclave tier is the device's and nothing here
/// says anything about it.
///
/// Skipped, with the reason, on a provider that does not advertise `ES256` DPoP proofs (Hydra
/// 26.2), as scenario 29 skips its PAR tests. Keycloak 26.4 sends no `DPoP-Nonce` of its own; the
/// nonce assertions are therefore made at the resource server, which demands one, and the
/// provider's side is asserted conditionally.
final class Scenario33DpopEndToEndTest: ProviderConformance {
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

    private func dpopConfiguration(
        binding: TokenBinding = .dpop(required: false), clientId: String = Provider.dpopClientId, origins: Set<String> = [Scenario33DpopEndToEndTest.origin]
    ) throws -> OAuthConfiguration {
        try configuration(clientId: clientId, protectedOrigins: origins, tokenBinding: binding)
    }

    private func sdkKey() throws -> P256.Signing.PrivateKey { try XCTUnwrap(dpopKeyStore.softwareKey, "the SDK generated no software DPoP key") }

    private func accessClaims(_ token: String) -> [String: Any] { DpopResourceServer.decode(token.split(separator: ".")[1].description) ?? [:] }

    private func jkt(of proof: [String: Any]?) throws -> String {
        let jwk = try XCTUnwrap(proof?["jwk"] as? [String: Any])
        return DpopResourceServer.thumbprint(x: try XCTUnwrap(jwk["x"] as? String), y: try XCTUnwrap(jwk["y"] as? String))
    }

    private func get(_ session: AuthenticatedSession, _ url: String) async throws -> HTTPURLResponse {
        try await session.data(for: URLRequest(url: URL(string: url)!)).1
    }

    func test33TheTokenRequestCarriesAValidProofAndTheIssuedTokenIsDpopBoundToTheSdksKey() async throws {
        let client = try await client(try dpopConfiguration())
        let metadata = try await client.metadata()

        try await client.login()

        let state = await client.sessionState
        XCTAssertEqual(state, .authenticated)
        // The tier is read back, not assumed (security.md).
        let attestation = try await client.keyAttestation()
        XCTAssertEqual(attestation, KeyAttestation(tier: .software))
        XCTAssertTrue(logger.warnings.contains { $0.contains("software-backed") }, "\(logger.warnings)")
        let jkt = DpopResourceServer.thumbprint(try sdkKey().publicKey)

        // The authorization request commits to the key (RFC 9449 section 10), pushed or not.
        let authorization: [String: String]
        if let par = metadata.pushedAuthorizationRequestEndpoint {
            authorization = try theRequest("POST", path(par)).form.compactMapValues(\.first)
        } else {
            authorization = query(try XCTUnwrap(browser.opened.first))
        }
        XCTAssertEqual(authorization["dpop_jkt"], jkt)

        let token = try theRequest("POST", path(metadata.tokenEndpoint))
        XCTAssertEqual(token.field("grant_type"), "authorization_code")
        let header = try XCTUnwrap(token.proofHeader)
        let claims = try XCTUnwrap(token.proofClaims)
        XCTAssertEqual(header["typ"] as? String, "dpop+jwt")
        XCTAssertEqual(header["alg"] as? String, "ES256")
        // A public key only: `d` in a proof's jwk would be the key itself.
        XCTAssertEqual(Set((header["jwk"] as? [String: Any] ?? [:]).keys), ["kty", "crv", "x", "y"])
        XCTAssertEqual(try self.jkt(of: header), jkt)
        XCTAssertEqual(claims["htm"] as? String, "POST")
        XCTAssertEqual(claims["htu"] as? String, metadata.tokenEndpoint)
        XCTAssertFalse((claims["jti"] as? String ?? "").isEmpty)
        XCTAssertLessThanOrEqual(abs((claims["iat"] as? Double ?? 0) - token.at.timeIntervalSince1970), 60)
        // No access token exists yet to hash.
        XCTAssertNil(claims["ath"])
        assertNoSecretOnTheWire(token)

        // What the provider issued: a DPoP token whose cnf.jkt is that key's thumbprint.
        XCTAssertEqual(token.status, 200)
        XCTAssertEqual(token.responseJSON?["token_type"] as? String, "DPoP")
        let accessToken = try XCTUnwrap(token.responseJSON?["access_token"] as? String)
        XCTAssertEqual((accessClaims(accessToken)["cnf"] as? [String: Any])?["jkt"] as? String, jkt)
        let issued = try await client.accessToken()
        XCTAssertEqual(issued.tokenType, "DPoP")

        try assertProviderNonceChallengesRetriedOnce(path(metadata.tokenEndpoint))
    }

    /// Keycloak 26.4 sends none; a provider that does must see exactly one retry carrying it.
    private func assertProviderNonceChallengesRetriedOnce(_ tokenPath: String) throws {
        let requests = network.matching("POST", tokenPath)
        for (index, entry) in requests.enumerated() {
            guard (400...401).contains(entry.status), let nonce = entry.responseHeader("DPoP-Nonce") else { continue }
            let retry = try XCTUnwrap(index + 1 < requests.count ? requests[index + 1] : nil, "a use_dpop_nonce challenge was not retried: \(entry)")
            XCTAssertEqual(retry.proofClaims?["nonce"] as? String, nonce)
            XCTAssertFalse((400...401).contains(retry.status) && retry.responseHeader("DPoP-Nonce") != nil, "retried more than once: \(requests)")
        }
    }

    func test33AnAuthenticatedCallSendsTheDpopSchemeAndAProofBoundToTheTokenWhichTheResourceServerAccepts() async throws {
        let rs = try await DpopResourceServer.install(network, origin: Self.origin)
        let client = try await client(try dpopConfiguration())
        try await client.login()
        let jkt = DpopResourceServer.thumbprint(try sdkKey().publicKey)
        let maybeClaims = await client.claims
        let subject = try XCTUnwrap(maybeClaims).subject

        let response = try await get(try client.authenticatedSession(), rs.url("/api/items?page=2"))

        XCTAssertEqual(response.statusCode, 200)
        let sent = try XCTUnwrap(network.transcript.first { $0.url.hasPrefix(Self.origin) })
        let authorization = try XCTUnwrap(sent.header("Authorization"))
        XCTAssertTrue(authorization.hasPrefix("DPoP "), authorization)
        let accessToken = String(authorization.dropFirst(5))
        let claims = try XCTUnwrap(sent.proofClaims)
        XCTAssertEqual(claims["htm"] as? String, "GET")
        // The URL without its query.
        XCTAssertEqual(claims["htu"] as? String, rs.url("/api/items"))
        XCTAssertEqual(claims["ath"] as? String, DpopResourceServer.sha256Url(accessToken))
        XCTAssertEqual(try self.jkt(of: sent.proofHeader), jkt)
        XCTAssertEqual((accessClaims(accessToken)["cnf"] as? [String: Any])?["jkt"] as? String, jkt)
        // What the server checked, not only what it answered: signature, htm, htu, iat, jti, ath and cnf.jkt.
        XCTAssertEqual(rs.attempts.map(\.verdict), [.accepted(jkt: jkt, subject: subject)])

        // An origin that is not protected gets neither the token nor a proof.
        let elsewhere = try await get(try client.authenticatedSession(), Provider.proxyOrigin + "/elsewhere")
        _ = elsewhere
        let unprotected = try XCTUnwrap(network.transcript.first { $0.url == Provider.proxyOrigin + "/elsewhere" })
        XCTAssertNil(unprotected.header("Authorization"))
        XCTAssertNil(unprotected.header("DPoP"))
    }

    func test33ANonceChallengeFromTheResourceServerIsRetriedOnceWithTheNonceAndRememberedForTheOrigin() async throws {
        let rs = try await DpopResourceServer.install(network, origin: Self.origin, nonce: "resource-nonce-1")
        let client = try await client(try dpopConfiguration())
        try await client.login()
        let session = try client.authenticatedSession()

        let first = try await get(session, rs.url("/api"))

        XCTAssertEqual(first.statusCode, 200)
        let sent = network.transcript.filter { $0.url.hasPrefix(Self.origin) }
        XCTAssertEqual(sent.count, 2, "exactly one retry: \(sent.map { "\($0.url) -> \($0.status)" })")
        guard sent.count == 2 else { return }
        XCTAssertEqual(sent[0].status, 401)
        XCTAssertEqual(sent[0].responseHeader("DPoP-Nonce"), "resource-nonce-1")
        XCTAssertTrue(sent[0].responseHeader("WWW-Authenticate")?.contains("use_dpop_nonce") == true)
        XCTAssertNil(sent[0].proofClaims?["nonce"])
        XCTAssertEqual(sent[1].proofClaims?["nonce"] as? String, "resource-nonce-1")
        // A fresh proof, not the first one resent.
        XCTAssertNotEqual(sent[0].proofClaims?["jti"] as? String, sent[1].proofClaims?["jti"] as? String)
        XCTAssertEqual(rs.attempts.compactMap { attempt -> DpopRefusal? in if case .refused(let reason) = attempt.verdict { return reason } else { return nil } }, [.nonceRequired])
        guard case .accepted? = rs.attempts.last?.verdict else { return XCTFail("the retry was not accepted: \(rs.attempts.map(\.verdict))") }

        // The nonce is per origin and kept: the next call needs no challenge.
        _ = try await get(session, rs.url("/api"))
        let afterwards = network.transcript.filter { $0.url.hasPrefix(Self.origin) }
        XCTAssertEqual(afterwards.count, 3)
        guard afterwards.count == 3 else { return }
        XCTAssertEqual(afterwards[2].proofClaims?["nonce"] as? String, "resource-nonce-1")
        XCTAssertEqual(afterwards[2].status, 200)
    }

    func test33AResourceServerThatKeepsChallengingGetsOneRetryAndThenNonceLoop() async throws {
        // It offers a nonce it will not accept: a client that retried on every challenge would never return.
        let rs = try await DpopResourceServer.install(network, origin: Self.origin, nonce: "demanded", offered: "offered")
        let client = try await client(try dpopConfiguration())
        try await client.login()
        let session = try client.authenticatedSession()

        let error = await oauthError { _ = try await self.get(session, rs.url("/api")) }

        guard case .recoverable(.nonceLoop)? = error else { return XCTFail("expected nonceLoop, got \(String(describing: error))") }
        XCTAssertEqual(rs.attempts.count, 2, "one request and one retry, no more: \(rs.attempts.map(\.verdict))")
    }

    func test33ARefreshKeepsTheKeyAndTheNewTokenIsBoundToIt() async throws {
        let rs = try await DpopResourceServer.install(network, origin: Self.origin)
        let client = try await client(try dpopConfiguration())
        let metadata = try await client.metadata()
        try await client.login()
        let jkt = DpopResourceServer.thumbprint(try sdkKey().publicKey)
        let before = try await client.accessToken().value

        try await client.refresh()

        let requests = network.matching("POST", path(metadata.tokenEndpoint))
        XCTAssertEqual(requests.count, 2)
        let login = requests[0], refresh = requests[1]
        XCTAssertEqual(refresh.field("grant_type"), "refresh_token")
        // The same key: the same jwk member for member, hence the same thumbprint, and a new jti.
        let loginJwk = login.proofHeader?["jwk"] as? [String: String]
        XCTAssertEqual(loginJwk, refresh.proofHeader?["jwk"] as? [String: String])
        XCTAssertEqual(try self.jkt(of: refresh.proofHeader), jkt)
        XCTAssertEqual(refresh.proofClaims?["htm"] as? String, "POST")
        XCTAssertEqual(refresh.proofClaims?["htu"] as? String, metadata.tokenEndpoint)
        XCTAssertNotEqual(login.proofClaims?["jti"] as? String, refresh.proofClaims?["jti"] as? String)
        XCTAssertNil(refresh.proofClaims?["ath"])

        XCTAssertEqual(refresh.status, 200)
        XCTAssertEqual(refresh.responseJSON?["token_type"] as? String, "DPoP")
        let after = try XCTUnwrap(refresh.responseJSON?["access_token"] as? String)
        XCTAssertNotEqual(before, after)
        XCTAssertEqual((accessClaims(after)["cnf"] as? [String: Any])?["jkt"] as? String, jkt)
        let current = try await client.accessToken().value
        XCTAssertEqual(after, current)

        // And the resource server takes the new token under the same key.
        let response = try await get(try client.authenticatedSession(), rs.url("/api"))
        XCTAssertEqual(response.statusCode, 200)
        XCTAssertEqual(network.transcript.last { $0.url.hasPrefix(Self.origin) }?.proofClaims?["ath"] as? String, DpopResourceServer.sha256Url(after))
        let maybeClaims = await client.claims
        let subject = try XCTUnwrap(maybeClaims).subject
        XCTAssertEqual(rs.attempts.map(\.verdict), [.accepted(jkt: jkt, subject: subject)])
    }

    /// What the binding is for: the access token, once stolen, is useless without the key. Each case
    /// changes exactly one thing from a request the resource server accepts (the control), so the
    /// refusal is that check's and nothing else's; the verdict's reason, not only the 401, is asserted.
    func test33AStolenAccessTokenIsRefusedWithoutTheKeyWithAnotherKeyAndWithAProofThatDoesNotMatch() async throws {
        let rs = try await DpopResourceServer.install(network, origin: Self.origin)
        let client = try await client(try dpopConfiguration())
        try await client.login()
        let token = try await client.accessToken().value
        let sdkKey = try sdkKey()
        try await rs.assertStolenTokenIsRefused(token: token, sdkKey: sdkKey)
        let url = rs.url("/api")

        // A proof the SDK itself sent is single use: replayed, it is refused for its jti alone.
        _ = try await get(try client.authenticatedSession(), url)
        let captured = try XCTUnwrap(network.transcript.last { $0.url.hasPrefix(Self.origin) }?.header("DPoP"))
        guard case .accepted? = rs.attempts.last?.verdict else { return XCTFail("the SDK's own call: \(String(describing: rs.attempts.last?.verdict))") }
        var replay = URLRequest(url: URL(string: url)!)
        replay.setValue("DPoP \(token)", forHTTPHeaderField: "Authorization")
        replay.setValue(captured, forHTTPHeaderField: "DPoP")
        _ = try await VirtualNetwork.session(record: false).data(for: replay)
        XCTAssertEqual(rs.attempts.last?.verdict, .refused(.replayedJti), "the SDK's own proof replayed")
    }

    func test33RequireHardwareOnAHostThatProducesASoftwareKeyIsRefusedWithHardwareBindingUnavailableBeforeAnyAuthorizationRequest() async throws {
        let client = try await client(try dpopConfiguration(binding: .dpop(required: true)))

        let error = await oauthError { try await client.login() }

        guard case .configuration(.hardwareBindingUnavailable)? = error else { return XCTFail("expected hardwareBindingUnavailable, got \(String(describing: error))") }
        // Nothing went to the authorization endpoint, the PAR endpoint or the token endpoint, and no browser opened.
        XCTAssertTrue(browser.opened.isEmpty, "\(browser.opened)")
        let metadata = try await client.metadata()
        let forbidden = [metadata.tokenEndpoint, metadata.authorizationEndpoint, metadata.pushedAuthorizationRequestEndpoint].compactMap { $0 }.map(path)
        XCTAssertTrue(network.transcript.allSatisfy { entry in !forbidden.contains { entry.path.hasSuffix($0) } }, "\(network.transcript.map { "\($0.method) \($0.url)" })")
        let state = await client.sessionState
        XCTAssertEqual(state, .unauthenticated)
        // The refused software key was not kept: a configuration that asked for hardware leaves none behind.
        XCTAssertNil(dpopKeyStore.softwareKey)
    }

    func test33AClientTheProviderRequiresDpopForGetsNoTokenFromAnSdkConfiguredForBearer() async throws {
        let client = try await client(try dpopConfiguration(binding: .bearer))
        let metadata = try await client.metadata()

        let error = await oauthError { try await client.login() }

        XCTAssertNotNil(error, "the provider issued a bearer token to a client that requires DPoP")
        let token = try XCTUnwrap(network.matching("POST", path(metadata.tokenEndpoint)).first)
        XCTAssertNil(token.header("DPoP"))
        XCTAssertEqual(token.status, 400, token.responseBody ?? "")
        XCTAssertNil(token.responseJSON?["access_token"])
        let state = await client.sessionState
        XCTAssertNotEqual(state, .authenticated)
    }

    func test33TheProviderBindsTheRefreshTokenToTheKeyAsWellSoWithoutTheKeyItBuysNothing() async throws {
        let client = try await client(try dpopConfiguration())
        let metadata = try await client.metadata()
        try await client.login()
        let refreshToken = try XCTUnwrap(network.matching("POST", path(metadata.tokenEndpoint)).first?.responseJSON?["refresh_token"] as? String)
        let attacker = P256.Signing.PrivateKey()

        func refresh(_ proof: String?) async throws -> Int {
            var request = URLRequest(url: URL(string: metadata.tokenEndpoint)!)
            request.httpMethod = "POST"
            request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
            if let proof { request.setValue(proof, forHTTPHeaderField: "DPoP") }
            request.httpBody = Data("grant_type=refresh_token&refresh_token=\(refreshToken)&client_id=\(Provider.dpopClientId)".utf8)
            return try await VirtualNetwork.session(record: false).data(for: request).1.statusCodeValue
        }

        let noProof = try await refresh(nil)
        let otherKey = try await refresh(DpopResourceServer.forgeProof(attacker, method: "POST", url: metadata.tokenEndpoint, accessToken: nil))
        XCTAssertEqual(noProof, 400)
        XCTAssertEqual(otherKey, 400)

        // Refused attempts did not spend it: the SDK, which holds the key, still refreshes.
        try await client.refresh()
        let state = await client.sessionState
        XCTAssertEqual(state, .authenticated)
    }
}

private extension URLResponse {
    var statusCodeValue: Int { (self as? HTTPURLResponse)?.statusCode ?? -1 }
}
