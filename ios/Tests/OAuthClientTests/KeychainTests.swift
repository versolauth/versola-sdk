import CryptoKit
import Security
import XCTest
@testable import OAuthClient

final class KeychainTests: XCTestCase {
    private func request(state: String = "state-1") -> PendingAuthorizationRequest {
        PendingAuthorizationRequest(
            state: state, nonce: "nonce-1", codeVerifier: "verifier-1", scopes: ["openid", "email"],
            redirectUri: "https://app.example.com/cb", acrValues: ["mfa"], maxAge: 300,
            createdAt: Date(timeIntervalSince1970: 1_800_000_000), resources: ["https://api.example.com"],
            issRequired: true, extensions: ["k": "v"]
        )
    }

    // MARK: in-memory stores (the logic the conformance driver and unit tests lean on)

    func testInMemoryCredentialStoreSavesReadsAndClears() async throws {
        let store = InMemoryCredentialStore()
        let initial = try await store.hasGrant()
        XCTAssertFalse(initial)
        try await store.save(refreshToken: "r1", rawIdToken: "id1")
        let hasGrant = try await store.hasGrant()
        let refresh = try await store.refreshToken()
        let idToken = try await store.rawIdToken()
        XCTAssertTrue(hasGrant)
        XCTAssertEqual(refresh, "r1")
        XCTAssertEqual(idToken, "id1")

        try await store.save(refreshToken: "r2", rawIdToken: nil)
        let rotated = try await store.refreshToken()
        let staleIdToken = try await store.rawIdToken()
        XCTAssertEqual(rotated, "r2")
        XCTAssertNil(staleIdToken, "an ID token must not outlive the grant it belonged to")

        try await store.clear()
        let afterClear = try await store.hasGrant()
        let clearedRefresh = try await store.refreshToken()
        XCTAssertFalse(afterClear)
        XCTAssertNil(clearedRefresh)
    }

    func testInMemoryPendingRotationRoundTripsAndClearsWithNil() async throws {
        let store = InMemoryCredentialStore()
        let empty = try await store.pendingRotation()
        XCTAssertNil(empty)
        try await store.savePendingRotation("key-1")
        let saved = try await store.pendingRotation()
        XCTAssertEqual(saved, "key-1")
        try await store.savePendingRotation("key-2")
        let replaced = try await store.pendingRotation()
        XCTAssertEqual(replaced, "key-2")
        try await store.savePendingRotation(nil)
        let cleared = try await store.pendingRotation()
        XCTAssertNil(cleared)
    }

    func testClearWipesTheRotationSlotToo() async throws {
        let store = InMemoryCredentialStore()
        try await store.save(refreshToken: "r", rawIdToken: nil)
        try await store.savePendingRotation("key")
        try await store.clear()
        let rotation = try await store.pendingRotation()
        XCTAssertNil(rotation)
    }

    func testInMemoryPendingStoreRoundTripsAndClears() async throws {
        let store = InMemoryPendingAuthorizationStore()
        let initial = try await store.load()
        XCTAssertNil(initial)
        try await store.save(request())
        let loaded = try await store.load()
        XCTAssertEqual(loaded, request())
        try await store.clear()
        let cleared = try await store.load()
        XCTAssertNil(cleared)
    }

    // MARK: pending request coding and keychain plumbing that need no keychain

    func testPendingRequestSurvivesJSONRoundTripIncludingTheDate() throws {
        let data = try PendingRequestCoding.encode(request())
        XCTAssertEqual(PendingRequestCoding.decode(data), request())
    }

    func testCorruptPendingRecordDecodesToNil() {
        XCTAssertNil(PendingRequestCoding.decode(Data("not json".utf8)))
        XCTAssertNil(PendingRequestCoding.decode(Data("{}".utf8)))
    }

    func testStoresThatAreOutOfReachForNowAreUnlockRequiredAndOtherStatusesAreConfigurationWithoutData() {
        XCTAssertEqual(KeychainItem.error(for: errSecInteractionNotAllowed), .recoverable(.unlockRequired))
        XCTAssertEqual(KeychainItem.error(for: -25308), .recoverable(.unlockRequired))
        // Transient: the store is not available yet (early boot) or authentication to it is withheld.
        XCTAssertEqual(KeychainItem.error(for: errSecNotAvailable), .recoverable(.unlockRequired))
        XCTAssertEqual(KeychainItem.error(for: errSecAuthFailed), .recoverable(.unlockRequired))
        // Permanent: nothing a retry changes, and nothing that signs the user out.
        for status in [errSecDecode, errSecParam, errSecMissingEntitlement, errSecDuplicateItem, errSecNoSuchAttr] {
            XCTAssertEqual(KeychainItem.error(for: status), .configuration(.invalidConfiguration(detail: "keychain error \(status)")))
        }
    }

    func testAStatusIsReadOffCryptoKitAndSecurityErrors() {
        XCTAssertEqual(KeychainFailure.status(of: CryptoKitError.underlyingCoreCryptoError(error: -25308)), -25308)
        XCTAssertEqual(KeychainFailure.status(of: NSError(domain: NSOSStatusErrorDomain, code: -25293)), -25293)
        XCTAssertNil(KeychainFailure.status(of: CryptoKitError.incorrectKeySize))
        XCTAssertNil(KeychainFailure.status(of: URLError(.timedOut)))
    }

    func testUnlockPolicyChoosesTheAccessibilityClass() {
        XCTAssertEqual(KeychainAccessibility(.none), .afterFirstUnlock)
        XCTAssertEqual(KeychainAccessibility(.onAppUnlock), .whenUnlocked)
        XCTAssertEqual(KeychainAccessibility.afterFirstUnlock.attribute as String, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String)
        XCTAssertEqual(KeychainAccessibility.whenUnlocked.attribute as String, kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String)
    }

    func testServiceNameIsDerivedFromTheStorageKey() {
        XCTAssertEqual(KeychainItem.service(forStorageKey: "abc"), "versola.oauth.abc")
    }

    // MARK: the real Keychain: device tier, opt-in

    /// Skipped unless `OAUTH_KEYCHAIN_TESTS=1`: a macOS host keychain prompts (or refuses
    /// outright, unsigned) where a simulator or device does not. Round-trips save, update, clear
    /// of all three credential items and the pending request.
    func testRealKeychainRoundTripsSaveUpdateAndClear() async throws {
        guard ProcessInfo.processInfo.environment["OAUTH_KEYCHAIN_TESTS"] == "1" else {
            throw XCTSkip("set OAUTH_KEYCHAIN_TESTS=1 to run against the real Keychain (device tier)")
        }
        let storageKey = "test-\(UUID().uuidString.prefix(8))"
        let credentials = KeychainCredentialStore(storageKey: storageKey, unlockPolicy: .none)
        let pending = KeychainPendingAuthorizationStore(storageKey: storageKey, unlockPolicy: .none)
        try await credentials.clear()
        try await pending.clear()

        let absent = try await credentials.hasGrant()
        XCTAssertFalse(absent)
        let absentRefresh = try await credentials.refreshToken()
        XCTAssertNil(absentRefresh)

        try await credentials.save(refreshToken: "r1", rawIdToken: "id1")
        let hasGrant = try await credentials.hasGrant()
        let refresh1 = try await credentials.refreshToken()
        let id1 = try await credentials.rawIdToken()
        XCTAssertTrue(hasGrant)
        XCTAssertEqual(refresh1, "r1")
        XCTAssertEqual(id1, "id1")

        try await credentials.save(refreshToken: "r2", rawIdToken: nil)
        let refresh2 = try await credentials.refreshToken()
        let id2 = try await credentials.rawIdToken()
        XCTAssertEqual(refresh2, "r2")
        XCTAssertNil(id2)

        try await credentials.savePendingRotation("rotation-1")
        let rotation = try await credentials.pendingRotation()
        XCTAssertEqual(rotation, "rotation-1")
        try await credentials.savePendingRotation(nil)
        let clearedRotation = try await credentials.pendingRotation()
        XCTAssertNil(clearedRotation)

        try await pending.save(request())
        let loaded = try await pending.load()
        XCTAssertEqual(loaded, request())
        try await pending.save(request(state: "state-2"))
        let updated = try await pending.load()
        XCTAssertEqual(updated?.state, "state-2")

        try await credentials.clear()
        try await pending.clear()
        let goneGrant = try await credentials.hasGrant()
        let gonePending = try await pending.load()
        XCTAssertFalse(goneGrant)
        XCTAssertNil(gonePending)
    }
}
