import Foundation
import os

/// Keychain items outlive the app that wrote them: deleting an app removes its container but not
/// its Keychain items, so an app reinstalled on the same device would open signed in as the
/// previous install's user, with that user's refresh token and DPoP key. Android has no such
/// leftover (its credentials are files under `noBackupFilesDir`), so this is the iOS half of the
/// same promise: what a user deletes with the app is gone.
///
/// The marker is a file in the client's cache directory (Application Support, excluded from
/// backup), written once the Keychain has been dealt with. It is the container's own state, so it
/// goes away with the app, and unlike `UserDefaults` it is not brought back by an iCloud restore
/// onto a device whose Keychain items are still there. A launch that finds no marker and an
/// empty directory is the first one of this container: whatever the Keychain holds for the client
/// is from an earlier install and is deleted before any store is read.
///
/// A launch that finds no marker and a *non-empty* directory is an upgrade from a version that
/// wrote none (0.1.0): its caches are there, so the container has run the SDK before and the
/// Keychain items are this install's own. The marker is written and nothing is deleted; without
/// that rule the first launch after the update would sign every existing user out.
///
/// Where it does not act, and why:
/// - **An app extension** (share, notification service, widget) has a container of its own, so its
///   first run sees an empty directory, but it did not just get installed: the host app's items may
///   be the ones in the Keychain, shared through a keychain access group. The guard is inert there
///   (`HostProcess`); it is the host app's first launch that decides.
/// - **A configured Keychain access group**: an item in a shared group is shared on purpose and
///   outlives any one app of the group, so one app's first launch must not delete what its
///   siblings are signed in with. The generic facade configures none and this is only built for
///   it; a caller that wires a group must not build the guard.
/// - **An App Clip** is a separate app with its own container and its own default access group, so
///   it is treated as an app: a clip's container is evicted while its Keychain items are not, which
///   is this problem exactly. The delete is scoped to the process's own default group
///   (`KeychainItem.deleteAllInOwnGroup`), never to a group shared with the full app.
package final class FirstLaunchGuard: Sendable {
    private static let markerName = "installed"

    private let marker: URL
    private let firstLaunchOfContainer: Bool
    private let inert: Bool
    private let deleteAll: @Sendable () throws -> Void
    private let settled = OSAllocatedUnfairLock(initialState: false)

    /// - Parameters:
    ///   - directory: the client's cache directory, which exists. Read here, at construction, not at
    ///     first use: a cache written in between (discovery runs on any operation) would make a
    ///     fresh container look like an upgrade.
    ///   - deleteAll: deletes every Keychain item of the client in the app's own access group, the
    ///     DPoP key and the pending request included.
    ///   - inert: true in an app extension: `ensure()` then does nothing at all.
    package init(directory: URL, inert: Bool = HostProcess.isAppExtension, deleteAll: @escaping @Sendable () throws -> Void) {
        self.inert = inert
        marker = directory.appendingPathComponent(Self.markerName)
        let entries = (try? FileManager.default.contentsOfDirectory(atPath: directory.path)) ?? []
        firstLaunchOfContainer = entries.isEmpty
        self.deleteAll = deleteAll
    }

    /// Settles the question once per process, before the caller touches the Keychain. A failure
    /// (a locked device cannot delete) leaves it open: the caller gets the error, which for a
    /// locked store is `unlockRequired`, and the next call tries again; no marker is written
    /// until the deletion has happened.
    package func ensure() throws {
        if inert { return }
        try settled.withLock { done in
            if done { return }
            if !FileManager.default.fileExists(atPath: marker.path) {
                if firstLaunchOfContainer { try deleteAll() }
                // Best effort: if it cannot be written the next launch asks again, and by then
                // the caches of a signed-in session have made the directory non-empty.
                try? Data().write(to: marker)
            }
            done = true
        }
    }
}

/// What kind of process the SDK is running in.
package enum HostProcess {
    /// An app extension: its bundle is an `.appex` and its Info.plist carries `NSExtension`.
    /// Either alone is enough, so a repackaged one cannot slip past the check that guards a
    /// delete. An App Clip is not an extension.
    static func isAppExtension(bundlePath: String, info: [String: Any]?) -> Bool {
        bundlePath.hasSuffix(".appex") || info?["NSExtension"] != nil
    }

    package static var isAppExtension: Bool {
        isAppExtension(bundlePath: Bundle.main.bundlePath, info: Bundle.main.infoDictionary)
    }
}
