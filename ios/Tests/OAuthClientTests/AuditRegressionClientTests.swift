import CryptoKit
import Foundation
import os
import XCTest
@testable import OAuthClient

/// A credential store that can be locked, as a Keychain is on a locked device: `hasGrant()` answers
/// from attributes, the reads throw `unlockRequired`.
actor LockableCredentialStore: CredentialStore {
    private let inner = InMemoryCredentialStore()
    private var locked = false
    func lock(_ value: Bool) { locked = value }
    private func check() throws { if locked { throw OAuthError.recoverable(.unlockRequired) } }
    func hasGrant() async throws -> Bool { try await inner.hasGrant() }
    func refreshToken() async throws -> String? { try check(); return try await inner.refreshToken() }
    func rawIdToken() async throws -> String? { try check(); return try await inner.rawIdToken() }
    func save(refreshToken: String, rawIdToken: String?) async throws { try await inner.save(refreshToken: refreshToken, rawIdToken: rawIdToken) }
    func saveRefreshed(refreshToken: String?, rawIdToken: String?) async throws { try await inner.saveRefreshed(refreshToken: refreshToken, rawIdToken: rawIdToken) }
    func savePendingRotation(_ idempotencyKey: String?) async throws { try await inner.savePendingRotation(idempotencyKey) }
    func pendingRotation() async throws -> String? { try await inner.pendingRotation() }
    func clear() async throws { try await inner.clear() }
}

/// Regression tests for the iOS audit (W1 to W21), client tier. Each asserts the CORRECT
/// behaviour, so each is red until its bug is fixed.
extension OAuthClientTests {
    /// What a previous process left: a grant and the ID token that went with it.
    func coldStartStore(locked: Bool = false) async throws -> LockableCredentialStore {
        let store = LockableCredentialStore()
        try await store.save(refreshToken: "rt-from-before", rawIdToken: Self.idToken(nonce: "n", audience: clientId))
        await store.lock(locked)
        return store
    }

    func coldStartClient(store: LockableCredentialStore) async throws -> OAuthClient {
        await OAuthClient.forgetAll()
        return try await OAuthClient.create(configuration: try configuration(), browser: browser, credentialStore: store, pendingStore: InMemoryPendingAuthorizationStore())
    }

    // MARK: - W5

    /// AUDIT: W5. `userInfo()` on a cold start with the store locked: `restoreClaims()` swallows the
    /// store's `unlockRequired` and the call fails as `reauthenticate(.grantRejected)`, which tells
    /// the app to sign the user out. It must say the store is locked.
    func testUserInfoWithALockedStoreSaysUnlockRequiredNotReauthenticate() async throws {
        let client = try await coldStartClient(store: try await coldStartStore(locked: true))

        do {
            let info = try await client.userInfo()
            XCTFail("returned \(info)")
        } catch let error as OAuthError {
            XCTAssertEqual(error, .recoverable(.unlockRequired))
        }
    }

    // MARK: - W13

    /// AUDIT: W13. After a cold start the state is `authenticated`, and `claims` must be there too.
    func testClaimsAreAvailableAfterAColdStartThatRestoredAnAuthenticatedSession() async throws {
        let client = try await coldStartClient(store: try await coldStartStore())

        let state = await client.sessionState
        XCTAssertEqual(state, .authenticated)
        let claims = await client.claims
        XCTAssertEqual(claims?.subject, "alice", "authenticated with no claims")
    }

    // MARK: - W12

    /// AUDIT: W12. A refresh an `AuthenticatedSession` triggers on a 401 runs inside an operation
    /// budget: the token request's timeout is bounded by the 20 s allowance, not the session's 60 s.
    func testTheRefreshAnAuthenticatedSessionTriggersRunsInsideTheOperationBudget() async throws {
        let client = try await client()
        try await client.login()
        let timeouts = OSAllocatedUnfairLock(initialState: [TimeInterval]())
        let apiCalls = OSAllocatedUnfairLock(initialState: 0)
        let browser = self.browser
        let clientId = self.clientId
        StubURLProtocol.install { request in
            let json = ["Content-Type": "application/json"]
            switch request.url!.path {
            case "/.well-known/openid-configuration": return .response(status: 200, headers: json, body: Data(Self.discovery().utf8))
            case "/jwks": return .response(status: 200, headers: json, body: Data(Self.jwks().utf8))
            case "/token":
                timeouts.withLock { $0.append(request.timeoutInterval) }
                let nonce = Self.blockingNonce(browser)
                let body = #"{"access_token":"at-2","token_type":"Bearer","expires_in":3600,"refresh_token":"rt-2","id_token":"\#(Self.idToken(nonce: nonce, audience: clientId))"}"#
                return .response(status: 200, headers: json, body: Data(body.utf8))
            case "/api":
                let call = apiCalls.withLock { value -> Int in value += 1; return value }
                return call == 1 ? .response(status: 401) : .response(status: 200, body: Data("ok".utf8))
            default: return .response(status: 404)
            }
        }

        let session = try client.authenticatedSession(origins: ["https://api.example.com"])
        let (_, response) = try await session.data(for: URLRequest(url: URL(string: "https://api.example.com/api")!))

        XCTAssertEqual(response.statusCode, 200)
        let seen = timeouts.withLock { $0 }
        XCTAssertEqual(seen.count, 1, "the 401 should have caused exactly one token request")
        XCTAssertLessThanOrEqual(seen.first ?? .infinity, 20.5, "the refresh ran outside an OperationBudget and got the session's own 60 s")
    }

    // MARK: - W18

    /// AUDIT: W18. A second `create()` for the same issuer and client id whose configuration differs
    /// only in the logger must not silently hand back the first client with the first logger.
    /// Chosen behaviour: it is refused like any other configuration mismatch.
    func testASecondCreateWithADifferentLoggerIsRefusedNotSilentlyIgnored() async throws {
        let first = RecordingLogger()
        let second = RecordingLogger()
        _ = try await OAuthClient.create(configuration: try configuration(logger: first), browser: browser, credentialStore: InMemoryCredentialStore(), pendingStore: InMemoryPendingAuthorizationStore())

        do {
            let again = try await OAuthClient.create(configuration: try configuration(logger: second), browser: browser, credentialStore: InMemoryCredentialStore(), pendingStore: InMemoryPendingAuthorizationStore())
            XCTFail("returned the first client, which logs to the first logger: \(again.configuration.clientId)")
        } catch let error as OAuthError {
            guard case .configuration(.invalidConfiguration) = error else { return XCTFail("\(error)") }
        }
    }
}

final class AuditKeyStore: DpopKeyStore {
    private let slot = OSAllocatedUnfairLock<Data?>(initialState: nil)
    func load() throws -> Data? { slot.withLock { $0 } }
    func save(_ data: Data) throws { slot.withLock { $0 = data } }
    func delete() throws { slot.withLock { $0 = nil } }
}

final class AuditClientTests: XCTestCase {
    override func tearDown() {
        StubURLProtocol.reset()
        super.tearDown()
    }

    // MARK: - W9

    /// AUDIT: W9. The delegates the SDK's own requests run under must refuse to store the response
    /// (`willCacheResponse` answers nil): a token response or key set must not land in the app
    /// session's `URLCache`. Neither delegate implements the method today.
    func testTheSDKsRequestDelegatesRefuseToCacheTheResponse() throws {
        let delegates: [(String, NSObject)] = [("NoRedirectDelegate", NoRedirectDelegate()), ("CacheAwareNoRedirectDelegate", CacheAwareNoRedirectDelegate())]
        for (name, delegate) in delegates {
            guard let dataDelegate = delegate as? URLSessionDataDelegate,
                  delegate.responds(to: #selector(URLSessionDataDelegate.urlSession(_:dataTask:willCacheResponse:completionHandler:)))
            else {
                XCTFail("\(name) does not implement urlSession(_:dataTask:willCacheResponse:)")
                continue
            }
            let url = URL(string: "https://id.example.com/token")!
            let task = StubURLProtocol.session().dataTask(with: url)
            let cached = CachedURLResponse(response: HTTPURLResponse(url: url, statusCode: 200, httpVersion: nil, headerFields: nil)!, data: Data("{}".utf8))
            let answered = expectation(description: "\(name) answered")
            let answer = OSAllocatedUnfairLock<CachedURLResponse?>(initialState: cached)
            dataDelegate.urlSession?(StubURLProtocol.session(), dataTask: task, willCacheResponse: cached) { result in
                answer.withLock { $0 = result }
                answered.fulfill()
            }
            wait(for: [answered], timeout: 2)
            XCTAssertNil(answer.withLock { $0 }, "\(name) let the response be cached")
        }
    }

    /// AUDIT: W9. The SDK's requests must neither read nor write the cache:
    /// `reloadIgnoringLocalAndRemoteCacheData`, where today only the local read is skipped.
    func testTheSDKsRequestsIgnoreTheLocalAndTheRemoteCache() async throws {
        StubURLProtocol.install { _ in .response(status: 200, body: Data("{}".utf8)) }
        let client = URLSessionHTTPClient(session: StubURLProtocol.session())

        _ = try await client.send(HTTPRequest(method: .get, url: URL(string: "https://id.example.com/jwks")!))

        let sent = try XCTUnwrap(StubURLProtocol.requests.first)
        XCTAssertEqual(sent.cachePolicy, .reloadIgnoringLocalAndRemoteCacheData)
    }

    // MARK: - W11

    /// AUDIT: W11. With `requireHardware == false`, a Secure Enclave that is reported present but
    /// refuses to make a key this once must not leave a software key persisted for good: the
    /// next launch must try the enclave again. (No grant is bound to the key here.)
    func testASoftwareKeyIsNotMadePermanentByATransientEnclaveRefusal() async throws {
        let store = AuditKeyStore()
        let attempts = OSAllocatedUnfairLock(initialState: 0)
        let refusing: @Sendable () throws -> SecureEnclave.P256.Signing.PrivateKey = {
            attempts.withLock { $0 += 1 }
            throw NSError(domain: "audit.enclave", code: 1)
        }
        let first = SecureEnclaveDpopKey(store: store, requireHardware: false, secureEnclaveAvailable: true, makeEnclaveKey: refusing)
        _ = try await first.publicJwk()

        let persisted = try store.load()
        XCTAssertNil(persisted, "the software fallback was persisted as the installation's key")

        let nextLaunch = SecureEnclaveDpopKey(store: store, requireHardware: false, secureEnclaveAvailable: true, makeEnclaveKey: refusing)
        _ = try await nextLaunch.publicJwk()
        let tried = attempts.withLock { $0 }
        XCTAssertEqual(tried, 2, "the second launch never asked the enclave again")
    }
}

/// The real Keychain: device tier, opt-in exactly as `KeychainTests.testRealKeychainRoundTripsSaveUpdateAndClear`
/// (a macOS host keychain refuses an unsigned process). Run on a simulator with
/// `TEST_RUNNER_OAUTH_KEYCHAIN_TESTS=1 xcodebuild test ...`.
final class AuditKeychainTests: XCTestCase {
    private func requireKeychain() throws {
        guard ProcessInfo.processInfo.environment["OAUTH_KEYCHAIN_TESTS"] == "1" else {
            throw XCTSkip("set OAUTH_KEYCHAIN_TESTS=1 to run against the real Keychain (device tier)")
        }
    }

    /// AUDIT: W6. `save()` is a new login or step-up: the rotation slot of the grant it replaces must
    /// go with it, or the next refresh replays a stale key against the new token.
    func testSavingALoginClearsTheRotationSlotOfThePreviousGrant() async throws {
        try requireKeychain()
        let storageKey = "audit-\(UUID().uuidString.prefix(8))"
        let store = KeychainCredentialStore(storageKey: storageKey, unlockPolicy: .none)
        defer { try? KeychainItem.deleteAllInOwnGroup(service: KeychainItem.service(forStorageKey: storageKey)) }
        try await store.save(refreshToken: "rt-old", rawIdToken: nil)
        try await store.savePendingRotation("key-of-rt-old")

        try await store.save(refreshToken: "rt-new", rawIdToken: nil)

        let slot = try await store.pendingRotation()
        XCTAssertNil(slot, "a stale slot survived the new grant")
    }

    /// AUDIT: W10. After the app's `unlockPolicy` changes, a successful read must migrate the item to
    /// the new accessibility class (today only a write sets `kSecAttrAccessible`).
    func testASuccessfulReadMigratesTheItemToTheCurrentUnlockPolicysClass() async throws {
        try requireKeychain()
        let storageKey = "audit-\(UUID().uuidString.prefix(8))"
        let service = KeychainItem.service(forStorageKey: storageKey)
        defer { try? KeychainItem.deleteAllInOwnGroup(service: service) }
        let before = KeychainCredentialStore(storageKey: storageKey, unlockPolicy: .none)
        try await before.save(refreshToken: "rt", rawIdToken: nil)
        let after = KeychainCredentialStore(storageKey: storageKey, unlockPolicy: .onAppUnlock)

        let read = try await after.refreshToken()
        XCTAssertEqual(read, "rt")

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: "refresh-token",
            kSecAttrSynchronizable as String: false, kSecUseDataProtectionKeychain as String: true,
            kSecReturnAttributes as String: true, kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var result: CFTypeRef?
        XCTAssertEqual(SecItemCopyMatching(query as CFDictionary, &result), errSecSuccess)
        let accessible = (result as? [String: Any])?[kSecAttrAccessible as String] as? String
        XCTAssertEqual(accessible, kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String)
    }
}
