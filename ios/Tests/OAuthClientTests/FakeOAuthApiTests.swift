import XCTest
import OAuthCore
@testable import OAuthClient

final class FakeOAuthApiTests: XCTestCase {

    func testLoginMovesTheStateToAuthenticatedAndRecordsTheCall() async throws {
        let api: any OAuthApi = FakeOAuthApi()

        try await api.login()

        let state = await api.sessionState
        XCTAssertEqual(state, .authenticated)
        let calls = await (api as! FakeOAuthApi).calls
        XCTAssertEqual(calls, ["login"])
    }

    func testAScriptedErrorIsThrownFromTheOperationTheAppWouldCall() async throws {
        let fake = FakeOAuthApi(state: .authenticated)
        await fake.setError(.reauthenticate(.sessionExpired))
        let api: any OAuthApi = fake

        do {
            _ = try await api.accessToken()
            XCTFail("expected the scripted error")
        } catch {
            XCTAssertEqual(error as? OAuthError, .reauthenticate(.sessionExpired))
        }
        let calls = await fake.calls
        XCTAssertEqual(calls, ["accessToken"])
    }

    func testLogoutDropsTheClaimsAndReportsTheScriptedOutcome() async {
        let fake = FakeOAuthApi(state: .authenticated)
        let outcome = await fake.logout(.default)

        XCTAssertEqual(outcome, LogoutOutcome(sessionEnded: true, tokenRevoked: true))
        let state = await fake.sessionState
        XCTAssertEqual(state, .unauthenticated)
    }

    func testSessionStatesYieldsTheCurrentStateFirst() async {
        let fake = FakeOAuthApi(state: .authenticated)
        var iterator = await fake.sessionStates().makeAsyncIterator()

        let first = await iterator.next()
        XCTAssertEqual(first, .authenticated)
    }
}
