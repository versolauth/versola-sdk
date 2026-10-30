import Foundation
import OAuthCore
import os
import XCTest
@testable import OAuthClient
@testable import versola_oauth

/// `29-pushed-authorization-request` through the bridge: PAR when advertised, required when the
/// provider says so, and the policy (`PushedAuthorizationMessage`) honoured as the native facade
/// honours it. Source: `Scenario29PushedAuthorizationTest`; the two tests that need a PAR
/// endpoint are skipped where the provider advertises none (Hydra), as the native ones are.
final class Scenario29PushedAuthorizationBridgeTest: BridgeConformance {
    private static let discovery = "/.well-known/openid-configuration"

    func test29LoginPushesTheRequestAndOpensTheBrowserWithClientIdAndRequestUriOnly() async throws {
        let bridge = try await bridge()
        let metadata = try await bridge.native.metadata()
        guard let parEndpoint = metadata.pushedAuthorizationRequestEndpoint else { throw XCTSkip("the provider advertises no PAR endpoint") }
        // The moment the browser opens: the state (Authorizing only once the pending request is
        // persisted), how much of the transcript preceded it, and when. The state is asked
        // through the bridge, from the browser leg.
        struct AtOpen: Sendable { var state: SessionStateMessage?; var transcriptCount = -1; var at = Date.distantPast }
        let atOpen = OSAllocatedUnfairLock(initialState: AtOpen())
        let network = self.network
        let dart = bridge.dart
        browser.onOpen { _ in
            let state = try? await dart.sessionState()
            atOpen.withLock { $0 = AtOpen(state: state, transcriptCount: network.transcript.count, at: Date()) }
        }

        try ok(await dart.login())

        let pushed = try theRequest("POST", path(parEndpoint))
        let opening = atOpen.withLock { $0 }
        // Persisted after the PAR response and before the browser opened.
        XCTAssertEqual(opening.state, .authorizing)
        let pushedIndex = try XCTUnwrap(network.transcript.firstIndex { $0.method == "POST" && $0.path.hasSuffix(path(parEndpoint)) })
        XCTAssertLessThan(pushedIndex, opening.transcriptCount)
        // The request_uri was used once, within the lifetime the PAR response gave it.
        let expiresIn = try XCTUnwrap((pushed.responseJSON?["expires_in"] as? NSNumber)?.doubleValue)
        let elapsed = opening.at.timeIntervalSince(pushed.at)
        XCTAssertLessThan(elapsed, expiresIn, "opened \(elapsed) s after a PAR response valid for \(expiresIn) s")
        XCTAssertEqual(browser.opened.filter { $0.absoluteString.contains("request_uri=") }.count, 1)
        XCTAssertNotNil(pushed.form["code_challenge"])
        XCTAssertNotNil(pushed.form["state"])
        XCTAssertNotNil(pushed.form["nonce"])
        XCTAssertEqual(pushed.field("redirect_uri"), Provider.redirectUri)
        assertNoSecretOnTheWire(pushed)
        XCTAssertEqual(browser.opened.count, 1)
        let opened = try XCTUnwrap(browser.opened.first)
        XCTAssertTrue(opened.absoluteString.hasPrefix(metadata.authorizationEndpoint + "?"))
        XCTAssertEqual(Set(query(opened).keys), ["client_id", "request_uri"])
        let state = try await dart.sessionState()
        XCTAssertEqual(state, .authenticated)
    }

    func test29APARRejectionSurfacesAsAuthorizationRejectedBeforeTheBrowserOpens() async throws {
        // An unregistered redirect URI: the provider's PAR endpoint refuses it with invalid_request.
        let bridge = try await bridge(redirectUri: "https://conformance.example.com/not-registered")
        let metadata = try await bridge.native.metadata()
        guard metadata.pushedAuthorizationRequestEndpoint != nil else { throw XCTSkip("the provider advertises no PAR endpoint") }

        let error = try failure(await bridge.dart.login())

        assertError(error, .configuration, "authorizationRejected")
        XCTAssertEqual(error.code, "invalid_request")
        XCTAssertTrue(browser.opened.isEmpty)
        // No pending request persisted: the state is not Authorizing.
        let state = try await bridge.dart.sessionState()
        XCTAssertEqual(state, .unauthenticated)
    }

    func test29AProviderThatRequiresPARUnderAPolicyOfNeverIsProviderUnsupportedNamingPar() async throws {
        network.rewriteJSON(Self.discovery) { document in
            var copy = document
            copy["require_pushed_authorization_requests"] = true
            return copy
        }
        let bridge = try await bridge(pushedAuthorization: .never)
        let metadata = try await bridge.native.metadata()

        let error = try failure(await bridge.dart.login())

        assertError(error, .configuration, "providerUnsupported")
        XCTAssertEqual(error.capability, "par")
        XCTAssertTrue(browser.opened.isEmpty)
        XCTAssertFalse(network.transcript.contains { $0.url.hasPrefix(metadata.authorizationEndpoint) })
        // Nothing was pushed either, where there is an endpoint to push to.
        if let par = metadata.pushedAuthorizationRequestEndpoint {
            XCTAssertTrue(network.matching("POST", path(par)).isEmpty)
        }
    }

    func test29AProviderWithoutAPAREndpointUnderAPolicyOfRequiredIsProviderUnsupportedNamingPar() async throws {
        network.rewriteJSON(Self.discovery) { document in
            var copy = document
            copy.removeValue(forKey: "pushed_authorization_request_endpoint")
            return copy
        }
        let bridge = try await bridge(pushedAuthorization: .required)

        let error = try failure(await bridge.dart.login())

        assertError(error, .configuration, "providerUnsupported")
        XCTAssertEqual(error.capability, "par")
        XCTAssertTrue(browser.opened.isEmpty)
    }
}
