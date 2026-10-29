import Foundation
import OAuthCore
import XCTest
@testable import OAuthClient

/// `24-generic-happy-path`: sign-in, authenticated call and sign-out through the generic facade.
final class Scenario24GenericHappyPathTest: ProviderConformance {
    func testSignInAuthenticatedCallUserInfoAndSignOutAgainstTheStagedProvider() async throws {
        let client = try await client()
        // Discovery first (the one request of it; the login reuses the cached document), for
        // the paths the assertions below are keyed on.
        let metadata = try await client.metadata()
        // The ID token must be validated before `authenticated` is published: the state the
        // SDK is in when it asks for the keys is the proof (second assertion).
        let stateAtJwksFetch = ResourceServer.Box<SessionState?>(nil)
        network.rewrite(path(metadata.jwksUri)) { body in
            let semaphore = DispatchSemaphore(value: 0)
            Task { stateAtJwksFetch.set(await client.sessionState); semaphore.signal() }
            semaphore.wait()
            return body
        }

        try await client.login()

        let state = await client.sessionState
        XCTAssertEqual(state, .authenticated)
        XCTAssertEqual(stateAtJwksFetch.get(), .authorizing)
        let maybeClaims = await client.claims
        let claims = try XCTUnwrap(maybeClaims)
        XCTAssertFalse(claims.subject.isEmpty)
        // The issuer as discovery announces it, trailing slash included (Hydra, Auth0).
        XCTAssertEqual(claims.issuer, metadata.issuer)

        // Exactly one discovery request; the request the browser opened is code + S256 with
        // state and nonce, in the query or pushed first (PAR when advertised).
        XCTAssertEqual(network.matching("GET", "/.well-known/openid-configuration").count, 1)
        let opened = try XCTUnwrap(browser.opened.first)
        XCTAssertEqual(browser.opened.count, 1)
        XCTAssertTrue(opened.absoluteString.hasPrefix(metadata.authorizationEndpoint + "?"))
        let parameters: [String: String]
        if let par = metadata.pushedAuthorizationRequestEndpoint {
            parameters = try theRequest("POST", path(par)).form.compactMapValues(\.first)
        } else {
            parameters = query(opened)
        }
        XCTAssertEqual(parameters["response_type"], "code")
        XCTAssertEqual(parameters["code_challenge_method"], "S256")
        XCTAssertNotNil(parameters["state"])
        XCTAssertNotNil(parameters["nonce"])
        XCTAssertFalse(network.transcript.contains { $0.field("client_secret") != nil })

        // The token request: a public client, the verifier, nothing non-standard.
        let token = try theRequest("POST", path(metadata.tokenEndpoint))
        XCTAssertEqual(token.field("grant_type"), "authorization_code")
        XCTAssertNotNil(token.field("code"))
        XCTAssertNotNil(token.field("code_verifier"))
        XCTAssertEqual(token.field("redirect_uri"), Provider.redirectUri)
        XCTAssertEqual(token.field("client_id"), Provider.clientId)
        assertNoSecretOnTheWire(token)
        XCTAssertNil(token.header("Idempotency-Key"))

        // The authenticated session attaches the token to the configured origin and nothing else.
        let session = try client.authenticatedSession()
        let (data, response) = try await session.data(for: URLRequest(url: URL(string: ResourceServer.origin + "/api")!))
        XCTAssertEqual(response.statusCode, 200)
        XCTAssertTrue(String(decoding: data, as: UTF8.self).contains(claims.subject))
        _ = try await session.data(for: URLRequest(url: URL(string: Provider.proxyOrigin + "/elsewhere")!))
        XCTAssertTrue(network.transcript.filter { $0.url.hasPrefix(ResourceServer.origin) }.allSatisfy { $0.header("Authorization")?.hasPrefix("Bearer ") == true })
        XCTAssertNil(network.transcript.first { $0.url == Provider.proxyOrigin + "/elsewhere" }?.header("Authorization"))

        let userInfo = try await client.userInfo()
        XCTAssertEqual(userInfo.subject, claims.subject)

        let outcome = await client.logout()

        let after = await client.sessionState
        XCTAssertEqual(after, .unauthenticated)
        let claimsAfter = await client.claims
        XCTAssertNil(claimsAfter)
        XCTAssertEqual(outcome.tokenRevoked, metadata.revocationEndpoint != nil)
        XCTAssertEqual(outcome.sessionEnded, metadata.endSessionEndpoint != nil)
        if let revocation = metadata.revocationEndpoint {
            let revoke = try theRequest("POST", path(revocation))
            XCTAssertEqual(revoke.field("token_type_hint"), "refresh_token")
            XCTAssertEqual(revoke.field("client_id"), Provider.clientId)
            assertNoSecretOnTheWire(revoke)
            // RFC 7009's observable for a public client: the revoked refresh token no longer buys a token.
            let refreshToken = try XCTUnwrap(token.responseJSON?["refresh_token"] as? String)
            var replay = URLRequest(url: URL(string: metadata.tokenEndpoint)!)
            replay.httpMethod = "POST"
            replay.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
            replay.httpBody = Data("grant_type=refresh_token&refresh_token=\(refreshToken)&client_id=\(Provider.clientId)".utf8)
            let (replayBody, replayResponse) = try await VirtualNetwork.session(record: false).data(for: replay)
            XCTAssertEqual((replayResponse as! HTTPURLResponse).statusCode, 400, String(decoding: replayBody, as: UTF8.self))
            XCTAssertTrue(String(decoding: replayBody, as: UTF8.self).contains("invalid_grant"))
        }
        if let endSession = metadata.endSessionEndpoint {
            let last = try XCTUnwrap(browser.opened.last)
            XCTAssertTrue(last.absoluteString.hasPrefix(endSession + "?"))
            XCTAssertNotNil(query(last)["id_token_hint"])
            XCTAssertEqual(query(last)["post_logout_redirect_uri"], Provider.postLogoutRedirectUri)
        }
        // The store holds nothing credential-shaped: the next token is a sign-in, not a refresh.
        let error = await oauthError { _ = try await client.accessToken() }
        guard case .reauthenticate = error else { return XCTFail("\(String(describing: error))") }
        XCTAssertEqual(network.matching("POST", path(metadata.tokenEndpoint)).count, 1)
    }
}
