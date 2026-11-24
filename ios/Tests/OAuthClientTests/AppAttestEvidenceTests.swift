import DeviceCheck
import Foundation
import os
import XCTest
@testable import OAuthClient
@testable import OAuthCore

/// The evidence an iOS app gives edge, against a scripted App Attest: App Attest itself runs on a device
/// with the capability, which is the device tier, and is not modelled here.
final class AppAttestEvidenceTests: XCTestCase {
    private func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }

    private func hash(_ jti: String) -> Data { NativeAttestation.clientDataHash(clientId: "mobile-app", jkt: "JKT", jti: jti) }

    private func evidence(
        _ service: FakeAppAttest, _ store: any AppAttestKeyStore = InMemoryAppAttestKeyStore()
    ) -> AppAttestEvidence {
        AppAttestEvidence(service: service, store: store)
    }

    private func fields(_ evidence: AppAttestEvidence, jti: String) async throws -> [String: String] {
        try await fieldsOf(evidence, jti: jti)
    }

    // MARK: attesting once, then asserting

    func testTheFirstRequestAttestsANewKeyForThatRequestAndLaterOnesAssert() async throws {
        let service = FakeAppAttest()
        let source = evidence(service)

        let first = try await fields(source, jti: "j1")
        let second = try await fields(source, jti: "j2")

        XCTAssertEqual(first["attestation_platform"], "ios")
        XCTAssertEqual(first["attestation_key_id"], "key-1")
        XCTAssertEqual(first["attestation_object"], Data("attestation-of-key-1".utf8).base64EncodedString())
        XCTAssertNil(first["attestation_assertion"])
        XCTAssertEqual(second["attestation_key_id"], "key-1")
        XCTAssertEqual(second["attestation_assertion"], Data("assertion-of-key-1".utf8).base64EncodedString())
        XCTAssertNil(second["attestation_object"], "an attestation object is never handed out twice")
        // One key, made once; each request's own hash went to App Attest, so each is good for that proof only.
        XCTAssertEqual(service.calls, [
            "generateKey",
            "attestKey:key-1:\(hex(hash("j1")))",
            "generateAssertion:key-1:\(hex(hash("j2")))",
        ])
    }

    func testTheStateIsSavedAsAttestedWhenTheObjectIsHandedOut() async throws {
        let store = InMemoryAppAttestKeyStore()

        _ = try await fields(evidence(FakeAppAttest(), store), jti: "j1")

        let state = try await store.load()
        XCTAssertEqual(state, AppAttestKeyState(keyId: "key-1", attested: true))
    }

    func testTheKeySurvivesANewEvidenceSourceOverTheSameStore() async throws {
        let store = InMemoryAppAttestKeyStore()
        let service = FakeAppAttest()
        _ = try await fields(evidence(service, store), jti: "j1")

        let later = try await fields(evidence(service, store), jti: "j2")

        XCTAssertNotNil(later["attestation_assertion"])
        XCTAssertNil(later["attestation_object"])
        XCTAssertEqual(service.calls.filter { $0 == "generateKey" }.count, 1)
    }

    // MARK: evidence is never a reason to fail

    func testADeviceWithoutAppAttestSendsNoEvidenceAndTouchesNothing() async throws {
        let service = FakeAppAttest(supported: false)
        let store = InMemoryAppAttestKeyStore()

        let result = try await evidence(service, store).fields(clientId: "mobile-app", jkt: "JKT", jti: "j1")

        XCTAssertTrue(result.isEmpty)
        XCTAssertTrue(service.calls.isEmpty)
        let state = try await store.load()
        XCTAssertNil(state)
    }

    func testAppleServiceOutOfReachIsNoEvidenceAndTheKeyIsKeptForTheNextTry() async throws {
        let service = FakeAppAttest()
        let store = InMemoryAppAttestKeyStore()
        let source = evidence(service, store)
        service.failNext("attestKey", with: AppAttestFailure.unavailable)

        let down = try await source.fields(clientId: "mobile-app", jkt: "JKT", jti: "j1")
        let state = try await store.load()
        let back = try await fields(source, jti: "j2")

        XCTAssertTrue(down.isEmpty)
        XCTAssertEqual(state, AppAttestKeyState(keyId: "key-1", attested: false))
        XCTAssertEqual(back["attestation_key_id"], "key-1", "the key was never attested, so it is attested now")
        XCTAssertNotNil(back["attestation_object"])
        XCTAssertEqual(service.calls.filter { $0 == "generateKey" }.count, 1)
    }

    func testAnUnsupportedOrUnknownFailureIsNoEvidenceAndChangesNothing() async throws {
        for failure in [AppAttestFailure.unsupported, .other] {
            let service = FakeAppAttest()
            let store = InMemoryAppAttestKeyStore()
            service.failNext("generateKey", with: failure)

            let result = try await evidence(service, store).fields(clientId: "mobile-app", jkt: "JKT", jti: "j1")

            XCTAssertTrue(result.isEmpty, "\(failure)")
            let state = try await store.load()
            XCTAssertNil(state, "\(failure)")
        }
    }

    func testAKeyAppAttestDoesNotKnowIsDroppedAndTheNextRequestAttestsANewOne() async throws {
        // A Keychain item that outlived its app, or a restore onto another device: the key id is there, the key is not.
        let store = InMemoryAppAttestKeyStore(AppAttestKeyState(keyId: "old-key", attested: true))
        let service = FakeAppAttest()
        let source = evidence(service, store)
        service.failNext("generateAssertion", with: AppAttestFailure.invalidKey)

        let result = try await fields(source, jti: "j1")
        let state = try await store.load()

        // The same request carries a new key's attestation: a sign-in is not refused for the install's own leftovers.
        XCTAssertEqual(result["attestation_key_id"], "key-1")
        XCTAssertNotNil(result["attestation_object"])
        XCTAssertNil(result["attestation_assertion"])
        XCTAssertEqual(state, AppAttestKeyState(keyId: "key-1", attested: true))
        XCTAssertEqual(service.calls, [
            "generateAssertion:old-key:\(hex(hash("j1")))",
            "generateKey",
            "attestKey:key-1:\(hex(hash("j1")))",
        ])
    }

    func testAKeyAppAttestStillDoesNotKnowAfterTheSecondTryIsNoEvidenceAndLeavesNothingBehind() async throws {
        let store = InMemoryAppAttestKeyStore(AppAttestKeyState(keyId: "old-key", attested: true))
        let service = FakeAppAttest()
        service.failNext("generateAssertion", with: AppAttestFailure.invalidKey)
        service.failNext("attestKey", with: AppAttestFailure.invalidKey)

        let result = try await evidence(service, store).fields(clientId: "mobile-app", jkt: "JKT", jti: "j1")

        XCTAssertTrue(result.isEmpty, "one new key is tried, not as many as it takes")
        let state = try await store.load()
        XCTAssertNil(state)
        XCTAssertEqual(service.calls.filter { $0 == "generateKey" }.count, 1)
    }

    func testAnUnattestedKeyAppleAlreadyAttestedIsReplacedInTheSameCall() async throws {
        // The process died between `attestKey` and the save: the state says "not attested", Apple says otherwise.
        let store = InMemoryAppAttestKeyStore(AppAttestKeyState(keyId: "old-key", attested: false))
        let service = FakeAppAttest()
        service.failNext("attestKey", with: AppAttestFailure.invalidKey)

        let result = try await fields(evidence(service, store), jti: "j1")

        XCTAssertEqual(result["attestation_key_id"], "key-1")
        XCTAssertNotNil(result["attestation_object"])
    }

    func testAFailedSaveAfterTheAttestationIsThrownAndTheNextRequestRecovers() async throws {
        let store = FlakyKeyStore(failingSaves: [2])
        let service = FakeAppAttest()
        let source = evidence(service, store)

        do {
            _ = try await source.fields(clientId: "mobile-app", jkt: "JKT", jti: "j1")
            XCTFail("a Keychain that cannot be written is not 'no evidence'")
        } catch {
            XCTAssertEqual(error as? StoreDown, StoreDown())
        }
        // Apple attested key-1 but the state says it was not: it is attested again, Apple refuses, a new key is made.
        service.failNext("attestKey", with: AppAttestFailure.invalidKey)
        let recovered = try await fields(source, jti: "j2")

        XCTAssertEqual(recovered["attestation_key_id"], "key-2")
        XCTAssertNotNil(recovered["attestation_object"])
    }

    func testDiscardingTheKeyMakesTheNextRequestAttestANewOne() async throws {
        let service = FakeAppAttest()
        let source = evidence(service)
        _ = try await fields(source, jti: "j1")

        try await source.discardKey()
        let next = try await fields(source, jti: "j2")

        XCTAssertEqual(next["attestation_key_id"], "key-2")
        XCTAssertNotNil(next["attestation_object"])
    }

    // MARK: callers that overlap

    func testOverlappingCallsMakeAndAttestOneKeyBetweenThem() async throws {
        let service = FakeAppAttest()
        let source = evidence(service)

        async let first = fieldsOf(source, jti: "j1")
        async let second = fieldsOf(source, jti: "j2")
        async let third = fieldsOf(source, jti: "j3")
        let results = try await [first, second, third]

        XCTAssertEqual(service.calls.filter { $0 == "generateKey" }.count, 1)
        XCTAssertEqual(service.calls.filter { $0.hasPrefix("attestKey:") }.count, 1)
        XCTAssertEqual(service.calls.filter { $0.hasPrefix("generateAssertion:") }.count, 2)
        XCTAssertEqual(results.filter { $0["attestation_object"] != nil }.count, 1, "one object, for one request")
        XCTAssertEqual(Set(results.compactMap { $0["attestation_key_id"] }), ["key-1"])
    }

    func testDiscardingTheKeyWaitsForACallInFlight() async throws {
        let service = FakeAppAttest()
        let store = InMemoryAppAttestKeyStore()
        let source = evidence(service, store)

        async let call = fieldsOf(source, jti: "j1")
        async let discard: Void = source.discardKey()
        _ = try await call
        try await discard

        // The call finished first and the discard then ran: no late save brought a discarded key back.
        let state = try await store.load()
        XCTAssertNil(state)
    }

    // MARK: what is not softened

    func testAFailureOfTheStoreIsThrownAsTheOtherStoresThrowIt() async throws {
        let source = evidence(FakeAppAttest(), FailingKeyStore())

        do {
            _ = try await source.fields(clientId: "mobile-app", jkt: "JKT", jti: "j1")
            XCTFail("a Keychain that cannot be read is not 'no evidence'")
        } catch {
            XCTAssertEqual(error as? StoreDown, StoreDown())
        }
    }

    func testACancelledCallerStaysCancelledWhateverTheFrameworkThrows() async throws {
        let service = FakeAppAttest()
        service.failNext("generateKey", with: AppAttestFailure.other)

        let task = Task { () -> [NativeStartField] in
            withUnsafeCurrentTask { $0?.cancel() }
            return try await AppAttestEvidence(service: service, store: InMemoryAppAttestKeyStore())
                .fields(clientId: "mobile-app", jkt: "JKT", jti: "j1")
        }

        do {
            let result = try await task.value
            XCTFail("a cancelled caller got \(result) instead of staying cancelled")
        } catch {
            XCTAssertTrue(error is CancellationError)
        }
    }

    func testACancelledCallerStaysCancelled() async throws {
        let service = FakeAppAttest()
        service.failNext("generateKey", with: CancellationError())

        do {
            _ = try await evidence(service).fields(clientId: "mobile-app", jkt: "JKT", jti: "j1")
            XCTFail("cancellation is not 'no evidence'")
        } catch {
            XCTAssertTrue(error is CancellationError)
        }
    }

    // MARK: the real service's errors

    private func dc(_ code: DCError.Code) -> Error { DCError(_nsError: NSError(domain: DCError.errorDomain, code: code.rawValue)) }

    func testEveryDeviceCheckErrorIsOneOfTheFailuresTheSDKActsOn() {
        XCTAssertEqual(DeviceCheckAppAttestService.failure(of: dc(.featureUnsupported)) as? AppAttestFailure, .unsupported)
        XCTAssertEqual(DeviceCheckAppAttestService.failure(of: dc(.serverUnavailable)) as? AppAttestFailure, .unavailable)
        XCTAssertEqual(DeviceCheckAppAttestService.failure(of: dc(.invalidKey)) as? AppAttestFailure, .invalidKey)
        XCTAssertEqual(DeviceCheckAppAttestService.failure(of: dc(.invalidInput)) as? AppAttestFailure, .invalidKey)
        XCTAssertEqual(DeviceCheckAppAttestService.failure(of: dc(.unknownSystemFailure)) as? AppAttestFailure, .other)
        XCTAssertEqual(DeviceCheckAppAttestService.failure(of: URLError(.timedOut)) as? AppAttestFailure, .other)
        XCTAssertTrue(DeviceCheckAppAttestService.failure(of: CancellationError()) is CancellationError)
    }

    // MARK: the real Keychain: device tier, opt-in

    /// Skipped unless `OAUTH_KEYCHAIN_TESTS=1`, like the Keychain stores': a macOS host keychain prompts (or refuses).
    func testTheKeychainStoreRoundTripsTheKeyStateAndClearsIt() async throws {
        guard ProcessInfo.processInfo.environment["OAUTH_KEYCHAIN_TESTS"] == "1" else {
            throw XCTSkip("set OAUTH_KEYCHAIN_TESTS=1 to run against the real Keychain (device tier)")
        }
        let store = KeychainAppAttestKeyStore(storageKey: "app-attest-test-\(UUID().uuidString)")

        let empty = try await store.load()
        try await store.save(AppAttestKeyState(keyId: "key-1", attested: false))
        let saved = try await store.load()
        try await store.save(AppAttestKeyState(keyId: "key-1", attested: true))
        let updated = try await store.load()
        try await store.clear()
        let cleared = try await store.load()

        XCTAssertNil(empty)
        XCTAssertEqual(saved, AppAttestKeyState(keyId: "key-1", attested: false))
        XCTAssertEqual(updated, AppAttestKeyState(keyId: "key-1", attested: true))
        XCTAssertNil(cleared)
    }
}

/// The fields of a request, by name. At file scope so that the concurrent tests' closures capture only what is `Sendable`.
private func fieldsOf(_ evidence: AppAttestEvidence, jti: String) async throws -> [String: String] {
    let fields = try await evidence.fields(clientId: "mobile-app", jkt: "JKT", jti: jti)
    return Dictionary(fields.map { ($0.name, $0.value) }, uniquingKeysWith: { first, _ in first })
}

/// A scripted App Attest: `key-1`, `key-2`..., `attestation-of-<key>` and `assertion-of-<key>`, every call
/// recorded with the client data hash it was handed, and any call made to fail once.
private final class FakeAppAttest: AppAttestService, Sendable {
    private struct State: Sendable {
        var calls: [String] = []
        var keys = 0
        var failNext: [String: any Error] = [:]
    }

    private let state = OSAllocatedUnfairLock(initialState: State())
    private let supported: Bool

    init(supported: Bool = true) { self.supported = supported }

    var isSupported: Bool { supported }
    var calls: [String] { state.withLock { $0.calls } }

    func failNext(_ operation: String, with error: any Error) {
        state.withLock { $0.failNext[operation] = error }
    }

    private func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }

    func generateKey() async throws -> String {
        await Task.yield()
        return try state.withLock { state in
            state.calls.append("generateKey")
            if let error = state.failNext.removeValue(forKey: "generateKey") { throw error }
            state.keys += 1
            return "key-\(state.keys)"
        }
    }

    func attestKey(_ keyId: String, clientDataHash: Data) async throws -> Data {
        await Task.yield()
        return try state.withLock { state in
            state.calls.append("attestKey:\(keyId):\(hex(clientDataHash))")
            if let error = state.failNext.removeValue(forKey: "attestKey") { throw error }
            return Data("attestation-of-\(keyId)".utf8)
        }
    }

    func generateAssertion(_ keyId: String, clientDataHash: Data) async throws -> Data {
        await Task.yield()
        return try state.withLock { state in
            state.calls.append("generateAssertion:\(keyId):\(hex(clientDataHash))")
            if let error = state.failNext.removeValue(forKey: "generateAssertion") { throw error }
            return Data("assertion-of-\(keyId)".utf8)
        }
    }
}

private struct StoreDown: Error, Equatable {}

private struct FailingKeyStore: AppAttestKeyStore {
    func load() async throws -> AppAttestKeyState? { throw StoreDown() }
    func save(_ state: AppAttestKeyState) async throws { throw StoreDown() }
    func clear() async throws { throw StoreDown() }
}

/// A store whose n-th `save` fails (counting from 1), and otherwise behaves like the in-memory one.
private actor FlakyKeyStore: AppAttestKeyStore {
    private var state: AppAttestKeyState?
    private var saves = 0
    private let failingSaves: Set<Int>

    init(failingSaves: Set<Int>) { self.failingSaves = failingSaves }

    func load() async throws -> AppAttestKeyState? { state }

    func save(_ state: AppAttestKeyState) async throws {
        saves += 1
        if failingSaves.contains(saves) { throw StoreDown() }
        self.state = state
    }

    func clear() async throws { state = nil }
}
