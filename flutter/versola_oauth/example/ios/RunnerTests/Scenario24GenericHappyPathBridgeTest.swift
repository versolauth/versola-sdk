import Foundation
import OAuthCore
import os
import XCTest
@testable import OAuthClient
@testable import versola_oauth

/// `24-generic-happy-path` through the bridge: sign-in, authenticated call and sign-out, every
/// operation sent through the plugin's host API. The assertions are the native driver's
/// (`Scenario24GenericHappyPathTest`); where the native test used what Flutter does not have (the
/// authenticated session), the call is the app's own, with the token `accessToken()` hands over,
/// and the half that asserted the session's origin matching has no bridge equivalent
/// (`spec/oauth-sdk-api.md` section 10).
final class Scenario24GenericHappyPathBridgeTest: BridgeConformance {
    func testBridgeSignInTheAppsOwnAuthenticatedCallUserInfoAndSignOutAgainstTheStagedProvider() async throws {
        let bridge = try await bridge()
        let dart = bridge.dart
        let subscription = try await dart.sessionStates()
        let sentAtSubscribe = messenger.sentOn(subscription.channel)
        // Discovery first (the one request of it; the login reuses the cached document), for
        // the paths the assertions below are keyed on.
        let metadata = try await bridge.native.metadata()
        // The ID token must be validated before `authenticated` is published: the state the SDK
        // is in when it asks for the keys is the proof (second assertion). Asked through the
        // bridge, from the proxy, while the login call is still open.
        let stateAtJwksFetch = OSAllocatedUnfairLock<SessionStateMessage?>(initialState: nil)
        network.rewrite(path(metadata.jwksUri)) { body in
            let state = try? await dart.sessionState()
            stateAtJwksFetch.withLock { $0 = state }
            return body
        }

        try ok(await dart.login())

        let state = try await dart.sessionState()
        XCTAssertEqual(state, .authenticated)
        // The native side sent the login's states on the event channel while the subscription was open.
        XCTAssertGreaterThan(messenger.sentOn(subscription.channel), sentAtSubscribe, "states sent during login")
        XCTAssertEqual(stateAtJwksFetch.withLock { $0 }, .authorizing)
        let maybeClaims = try await dart.claims()
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

        // The one credential that crosses: the access token, bearer, usable by the app at the
        // protected resource. The SDK itself sends nothing to the resource: attaching the token
        // is the app's (a Flutter app has no authenticated session, section 10).
        let accessToken = try self.token(await dart.accessToken())
        try await assertTokenIsUsableAtTheResource(accessToken, subject: claims.subject)
        XCTAssertFalse(network.transcript.contains { $0.url.hasPrefix(ResourceServer.origin) })

        let userInfo = try await dart.userInfo()
        XCTAssertEqual(try subject(userInfo), claims.subject)

        let outcome = try await dart.logout()

        let after = try await dart.sessionState()
        XCTAssertEqual(after, .unauthenticated)
        let claimsAfter = try await dart.claims()
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
            let (replayBody, replayResponse) = try await app.data(for: replay)
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
        let afterLogout = try await dart.accessToken()
        XCTAssertEqual(try failure(afterLogout).category, .reauthenticate)
        XCTAssertEqual(network.matching("POST", path(metadata.tokenEndpoint)).count, 1)

        // The state stream (flutter.md, Bridge): the seven states and no others, starting with the
        // restored one and ending where the session ended.
        try await until("the stream delivers the signed-out state") { subscription.states.last == .unauthenticated && subscription.states.contains(.authenticated) }
        XCTAssertEqual(subscription.states.first, .unauthenticated)
        XCTAssertGreaterThan(try XCTUnwrap(subscription.states.firstIndex(of: .authenticated)), 0)
        // Cancelling the Dart subscription ends the native consumption (flutter.md). The test's own
        // listener is gone either way, so what is counted is the native side's sends on the channel,
        // not Dart's receipts: nothing more is sent across the next login's state changes.
        try await subscription.cancel()
        let sentAtCancel = messenger.sentOn(subscription.channel)
        try ok(await dart.login())
        let last = try await dart.sessionState()
        XCTAssertEqual(last, .authenticated)
        XCTAssertEqual(messenger.sentOn(subscription.channel), sentAtCancel, "messages sent on the channel after cancel")
    }
}
