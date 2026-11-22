import Foundation
import XCTest
@testable import OAuthCore

/// `login(expectedSubject:)` and `sessionSubject()`: a step-up through a back channel that carries no
/// `id_token_hint` must come back as the user of the session (`spec/versola-sdk-api.md` section 6).
/// The Android `SessionCoordinatorTest`'s twin; the fixture is `SessionCoordinatorTests`'.
extension SessionCoordinatorTests {
    private func failure(_ block: () async throws -> Void) async -> OAuthError? {
        do {
            try await block()
            XCTFail("expected an OAuthError")
            return nil
        } catch {
            return error as? OAuthError
        }
    }

    // MARK: expectedSubject

    func testStepUpAnsweredByAnotherUserStoresNothingRevokesWhatWasIssuedAndLeavesTheSessionAsItWas() async throws {
        let first = response(refresh: "rt-1", subject: "alice")
        let f = try fixture(answers: [.success(first), .success(response(refresh: "rt-2", subject: "bob"))], policy: .required)
        try await f.coordinator.login(scopes: ["openid"])
        let accessBefore = try await f.coordinator.accessToken()

        let error = await failure { try await f.coordinator.login(scopes: ["openid"], expectedSubject: "alice") }

        XCTAssertEqual(error, .recoverable(.accountMismatch))
        XCTAssertEqual(error?.code, "recoverable.account_mismatch")
        // Nothing of the second sign-in was kept: the grant, the ID token and the claims are the first's.
        let refresh = await f.store.refresh
        let idToken = await f.store.idToken
        let clears = await f.store.clears
        let claims = await f.coordinator.claims
        XCTAssertEqual(refresh, "rt-1")
        XCTAssertEqual(idToken, first.idToken)
        XCTAssertEqual(claims?.subject, "alice")
        XCTAssertEqual(clears, 0)
        let accessAfter = try await f.coordinator.accessToken()
        XCTAssertEqual(accessAfter.value, accessBefore.value)
        let state = await f.flow.states.current
        XCTAssertEqual(state, .authenticated)
        let pending = await f.pendingStore.stored
        XCTAssertNil(pending, "the login is abandoned as a failed one is")
        // What the provider issued to the wrong user is revoked, and only that (detached, so awaited with a bound).
        await AuthzKit.waitUntil("the refused refresh token is revoked") { await f.tokens.calls.contains(.revoke("rt-2")) }
        let revocations = await f.tokens.calls.filter { if case .revoke = $0 { return true } else { return false } }
        XCTAssertEqual(revocations, [.revoke("rt-2")])
    }

    func testStepUpAnsweredByTheSameUserSucceedsAndReplacesTheGrant() async throws {
        let second = response(refresh: "rt-2", subject: "alice")
        let f = try fixture(answers: [.success(response(refresh: "rt-1", subject: "alice")), .success(second)], policy: .required)
        try await f.coordinator.login(scopes: ["openid"])

        let issued = try await f.coordinator.login(scopes: ["openid"], expectedSubject: "alice")

        XCTAssertEqual(issued.accessToken, second.accessToken)
        let refresh = await f.store.refresh
        let idToken = await f.store.idToken
        let claims = await f.coordinator.claims
        let calls = await f.tokens.calls
        XCTAssertEqual(refresh, "rt-2")
        XCTAssertEqual(idToken, second.idToken)
        XCTAssertEqual(claims?.subject, "alice")
        XCTAssertFalse(calls.contains(.revoke("rt-2")))
        let state = await f.flow.states.current
        XCTAssertEqual(state, .authenticated)
    }

    func testSubjectDifferingOnlyByCaseOrATrailingSpaceIsAnotherUser() async throws {
        for other in ["Alice", "alice "] {
            let f = try fixture(answers: [.success(response(refresh: "rt-x", subject: other))], policy: .required)
            let error = await failure { try await f.coordinator.login(scopes: ["openid"], expectedSubject: "alice") }
            XCTAssertEqual(error, .recoverable(.accountMismatch), other)
            let refresh = await f.store.refresh
            XCTAssertNil(refresh, other)
        }
    }

    func testExpectedSubjectWithoutAValidatorCannotBeComparedAndIsRefusedTheSameWay() async throws {
        let f = try fixture(answers: [.success(response(refresh: "rt-1", subject: "alice"))], policy: .required, withoutValidator: true)

        let error = await failure { try await f.coordinator.login(scopes: ["openid"], expectedSubject: "alice") }

        XCTAssertEqual(error, .recoverable(.accountMismatch))
        let refresh = await f.store.refresh
        let claims = await f.coordinator.claims
        let state = await f.flow.states.current
        XCTAssertNil(refresh)
        XCTAssertNil(claims)
        XCTAssertEqual(state, .unauthenticated)
        await AuthzKit.waitUntil("the refused refresh token is revoked") { await f.tokens.calls.contains(.revoke("rt-1")) }
    }

    func testWithoutAnExpectedSubjectAnotherUsersLoginIsAnOrdinaryLogin() async throws {
        let f = try fixture(answers: [.success(response(refresh: "rt-1", subject: "alice")), .success(response(refresh: "rt-2", subject: "bob"))], policy: .required)
        try await f.coordinator.login(scopes: ["openid"])

        try await f.coordinator.login(scopes: ["openid"])

        let refresh = await f.store.refresh
        let claims = await f.coordinator.claims
        let calls = await f.tokens.calls
        XCTAssertEqual(refresh, "rt-2")
        XCTAssertEqual(claims?.subject, "bob")
        XCTAssertFalse(calls.contains { if case .revoke = $0 { return true } else { return false } })
    }

    func testIdTokenRejectedAfterTheExchangeRevokesTheRefreshTokenTheProviderIssued() async throws {
        // The path the account mismatch shares: the issued grant is a live credential no device holds.
        let f = try fixture(answers: [.success(response(refresh: "rt-1"))], policy: .required)
        await f.validator.reject(.nonce)

        let error = await failure { try await f.coordinator.login(scopes: ["openid"]) }

        XCTAssertEqual(error, .configuration(.idTokenRejected(.nonce)))
        let refresh = await f.store.refresh
        XCTAssertNil(refresh)
        await AuthzKit.waitUntil("the rejected response's refresh token is revoked") { await f.tokens.calls.contains(.revoke("rt-1")) }
    }

    // MARK: sessionSubject

    func testSessionSubjectIsTheSubOfTheStoredIdToken() async throws {
        let store = MemoryCredentials()
        try await store.save(refreshToken: "rt", rawIdToken: idToken(subject: "carol"))
        let f = try fixture(answers: [], store: store)

        let subject = try await f.coordinator.sessionSubject()

        XCTAssertEqual(subject, "carol")
    }

    func testSessionSubjectIsTheSubOfTheClaimsALoginValidated() async throws {
        let f = try fixture(answers: [.success(response(refresh: "rt-1", subject: "alice"))], policy: .required)
        try await f.coordinator.login(scopes: ["openid"])

        let subject = try await f.coordinator.sessionSubject()

        XCTAssertEqual(subject, "alice")
    }

    func testSessionSubjectIsNilWithNoSession() async throws {
        let f = try fixture(answers: [])

        let subject = try await f.coordinator.sessionSubject()

        XCTAssertNil(subject)
    }

    func testSessionSubjectIsNilWhenTheStoredIdTokenCannotBeReadAsClaims() async throws {
        let store = MemoryCredentials()
        try await store.save(refreshToken: "rt", rawIdToken: "not-a-jwt")
        let f = try fixture(answers: [], store: store)

        let subject = try await f.coordinator.sessionSubject()

        XCTAssertNil(subject)
    }

    func testSessionSubjectPropagatesAStoreThatCannotBeReadInsteadOfSwallowingIt() async throws {
        let store = MemoryCredentials()
        try await store.save(refreshToken: "rt", rawIdToken: idToken(subject: "carol"))
        await store.failIdTokenReads(.recoverable(.unlockRequired))
        let f = try fixture(answers: [], store: store)

        let error = await failure { _ = try await f.coordinator.sessionSubject() }

        XCTAssertEqual(error, .recoverable(.unlockRequired))
    }
}
