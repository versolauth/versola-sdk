import Foundation
import os
import XCTest
@testable import OAuthClient

/// A reinstalled app must not open signed in as the previous install's user: the Keychain
/// outlives the app, the container does not (`FirstLaunchGuard`). The Keychain itself is a
/// closure here; its real deletion is the device tier.
final class FirstLaunchGuardTests: XCTestCase {
    private var directory: URL!

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent("first-launch-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    }

    override func tearDown() {
        try? FileManager.default.removeItem(at: directory)
    }

    private final class Deletions: Sendable {
        private let lock = OSAllocatedUnfairLock(initialState: (count: 0, failing: false))
        var count: Int { lock.withLock { $0.count } }
        func fail(_ value: Bool) { lock.withLock { $0.failing = value } }
        func run() throws {
            try lock.withLock { state in
                state.count += 1
                if state.failing { throw OAuthError.recoverable(.unlockRequired) }
            }
        }
    }

    private func guardFor(_ deletions: Deletions, inert: Bool = false) -> FirstLaunchGuard {
        FirstLaunchGuard(directory: directory, inert: inert, deleteAll: { try deletions.run() })
    }

    private var markerExists: Bool { FileManager.default.fileExists(atPath: directory.appendingPathComponent("installed").path) }

    func testAFreshContainerDeletesWhatAPreviousInstallLeftInTheKeychainOnceAndWritesTheMarker() throws {
        let deletions = Deletions()
        let first = guardFor(deletions)

        try first.ensure()
        try first.ensure()

        XCTAssertEqual(deletions.count, 1, "once per process")
        XCTAssertTrue(markerExists)
    }

    func testALaterLaunchOfTheSameContainerDeletesNothing() throws {
        let deletions = Deletions()
        try guardFor(deletions).ensure()
        XCTAssertEqual(deletions.count, 1)

        // The next launch: a new guard over the same directory, now with caches beside the marker.
        try Data("{}".utf8).write(to: directory.appendingPathComponent("metadata.json"))
        try guardFor(deletions).ensure()

        XCTAssertEqual(deletions.count, 1, "the marker says this container's Keychain items are its own")
    }

    func testAnUpgradeFromAVersionThatWroteNoMarkerKeepsTheSessionAndWritesTheMarker() throws {
        // 0.1.0 left its caches and no marker. Deleting here would sign every existing user out on
        // the first launch after the update.
        try Data("{}".utf8).write(to: directory.appendingPathComponent("metadata.json"))
        let deletions = Deletions()

        try guardFor(deletions).ensure()

        XCTAssertEqual(deletions.count, 0)
        XCTAssertTrue(markerExists)
    }

    func testALockedKeychainLeavesTheQuestionOpenAndNoMarkerUntilTheDeletionHappens() throws {
        let deletions = Deletions()
        deletions.fail(true)
        let subject = guardFor(deletions)

        XCTAssertThrowsError(try subject.ensure()) { XCTAssertEqual($0 as? OAuthError, .recoverable(.unlockRequired)) }
        XCTAssertFalse(markerExists, "a stale session still in the Keychain must be deleted before the marker says it was")

        deletions.fail(false)
        try subject.ensure()

        XCTAssertEqual(deletions.count, 2)
        XCTAssertTrue(markerExists)
    }

    func testCacheWrittenBetweenConstructionAndFirstUseDoesNotTurnAFreshContainerIntoAnUpgrade() throws {
        let deletions = Deletions()
        let subject = guardFor(deletions)
        // Discovery ran before any store was read.
        try Data("{}".utf8).write(to: directory.appendingPathComponent("metadata.json"))

        try subject.ensure()

        XCTAssertEqual(deletions.count, 1)
    }

    func testRacingFirstUsesDeleteOnce() async throws {
        let deletions = Deletions()
        let subject = guardFor(deletions)
        try await withThrowingTaskGroup(of: Void.self) { group in
            for _ in 0..<50 { group.addTask { try subject.ensure() } }
            try await group.waitForAll()
        }
        XCTAssertEqual(deletions.count, 1)
    }

    func testTheGuardIsInertInAnAppExtensionAndDeletesNothingNorWritesAMarker() throws {
        // An extension has a container of its own, empty on its first run, and the Keychain items
        // in the app's shared access group are the host app's live session.
        let deletions = Deletions()
        let subject = guardFor(deletions, inert: true)

        try subject.ensure()
        try subject.ensure()

        XCTAssertEqual(deletions.count, 0)
        XCTAssertFalse(markerExists)
    }

    func testAnExtensionProcessIsRecognisedByItsBundleOrItsInfoPlistAndAnAppOrAClipIsNot() {
        XCTAssertTrue(HostProcess.isAppExtension(bundlePath: "/var/containers/Bundle/Application/X/App.app/PlugIns/Share.appex", info: nil))
        XCTAssertTrue(HostProcess.isAppExtension(bundlePath: "/somewhere/Repackaged", info: ["NSExtension": ["NSExtensionPointIdentifier": "com.apple.share-services"]]))
        XCTAssertFalse(HostProcess.isAppExtension(bundlePath: "/var/containers/Bundle/Application/X/App.app", info: ["CFBundleIdentifier": "com.example.app"]))
        XCTAssertFalse(HostProcess.isAppExtension(bundlePath: "/var/containers/Bundle/Application/X/Clip.app", info: ["NSAppClip": ["NSAppClipRequestEphemeralUserNotification": false]]), "an App Clip is an app")
    }

    func testTheKeychainStoresGoThroughTheGuardBeforeAnyRead() async throws {
        // A store with a guard that refuses reports the guard's error and reads nothing.
        let subject = FirstLaunchGuard(directory: directory, deleteAll: { throw OAuthError.recoverable(.unlockRequired) })
        let credentials = KeychainCredentialStore(storageKey: "guarded-\(UUID().uuidString.prefix(8))", unlockPolicy: .none, firstLaunch: subject)
        let pending = KeychainPendingAuthorizationStore(storageKey: "guarded-\(UUID().uuidString.prefix(8))", unlockPolicy: .none, firstLaunch: subject)
        let key = KeychainDpopKeyStore(storageKey: "guarded-\(UUID().uuidString.prefix(8))", firstLaunch: subject)
        do { _ = try await credentials.hasGrant(); XCTFail("credentials read before the guard") } catch { XCTAssertEqual(error as? OAuthError, .recoverable(.unlockRequired)) }
        do { _ = try await credentials.refreshToken(); XCTFail("credentials read before the guard") } catch { XCTAssertEqual(error as? OAuthError, .recoverable(.unlockRequired)) }
        do { _ = try await pending.load(); XCTFail("pending read before the guard") } catch { XCTAssertEqual(error as? OAuthError, .recoverable(.unlockRequired)) }
        XCTAssertThrowsError(try key.load()) { XCTAssertEqual($0 as? OAuthError, .recoverable(.unlockRequired)) }
    }
}
