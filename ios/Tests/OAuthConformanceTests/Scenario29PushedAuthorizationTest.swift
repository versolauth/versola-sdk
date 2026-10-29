import Foundation
import OAuthCore
import XCTest
@testable import OAuthClient

/// `29-pushed-authorization-request`: PAR when advertised, required when the provider says so,
/// and a rejection surfaces before the browser opens. The twin of the Android
/// `Scenario29PushedAuthorizationTest`; the two tests that need a PAR endpoint are skipped where
/// the provider advertises none (Hydra), as the Android ones are.
final class Scenario29PushedAuthorizationTest: ProviderConformance {
    private static let discovery = "/.well-known/openid-configuration"

    func test29LoginPushesTheRequestAndOpensTheBrowserWithClientIdAndRequestUriOnly() async throws {
        let client = try await client()
        let metadata = try await client.metadata()
        guard let parEndpoint = metadata.pushedAuthorizationRequestEndpoint else { throw XCTSkip("the provider advertises no PAR endpoint") }
        // The moment the browser opens: the state (Authorizing only once the pending request
        // is persisted), how much of the transcript preceded it, and when.
        struct AtOpen: Sendable { var state: SessionState?; var transcriptCount = -1; var at = Date.distantPast }
        let atOpen = ResourceServer.Box(AtOpen())
        let network = self.network
        browser.onOpen { _ in
            // The hook is synchronous; the state lives behind the client's actors.
            let semaphore = DispatchSemaphore(value: 0)
            let state = ResourceServer.Box<SessionState?>(nil)
            Task { state.set(await client.sessionState); semaphore.signal() }
            _ = semaphore.wait(timeout: .now() + 10)
            atOpen.set(AtOpen(state: state.get(), transcriptCount: network.transcript.count, at: Date()))
        }

        try await client.login()

        let pushed = try theRequest("POST", path(parEndpoint))
        let opening = atOpen.get()
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
        let state = await client.sessionState
        XCTAssertEqual(state, .authenticated)
    }

    func test29APARRejectionSurfacesAsAuthorizationRejectedBeforeTheBrowserOpens() async throws {
        // An unregistered redirect URI: the provider's PAR endpoint refuses it with invalid_request.
        let client = try await client(try configuration(redirectUri: "https://conformance.example.com/not-registered"))
        let metadata = try await client.metadata()
        guard metadata.pushedAuthorizationRequestEndpoint != nil else { throw XCTSkip("the provider advertises no PAR endpoint") }

        let error = await oauthError { try await client.login() }

        guard case .configuration(.authorizationRejected(let code, _))? = error else {
            return XCTFail("expected authorizationRejected, got \(String(describing: error))")
        }
        XCTAssertEqual(code, "invalid_request")
        XCTAssertTrue(browser.opened.isEmpty)
        // No pending request persisted: the state is not Authorizing.
        let state = await client.sessionState
        XCTAssertEqual(state, .unauthenticated)
    }

    func test29AProviderThatRequiresPARUnderAPolicyOfNeverIsProviderUnsupportedNamingPar() async throws {
        network.rewriteJSON(Self.discovery) { document in
            var copy = document
            copy["require_pushed_authorization_requests"] = true
            return copy
        }
        let client = try await client(try configuration(pushedAuthorization: .never))
        let metadata = try await client.metadata()

        let error = await oauthError { try await client.login() }

        XCTAssertEqual(error, .configuration(.providerUnsupported(capability: "par")))
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
        let client = try await client(try configuration(pushedAuthorization: .required))

        let error = await oauthError { try await client.login() }

        XCTAssertEqual(error, .configuration(.providerUnsupported(capability: "par")))
        XCTAssertTrue(browser.opened.isEmpty)
    }
}
