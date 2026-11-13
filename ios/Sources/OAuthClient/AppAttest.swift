import DeviceCheck
import Foundation
import OAuthCore

// Apple's App Attest as the iOS half of the evidence edge can ask an app for on `/native/start`
// (`spec/server-dependencies.md`, "App attestation on `/native/start`"). Nothing here is reachable
// from the public surface and nothing in the SDK calls it yet: the Versola facade that would is not
// on iOS. It is built and tested now so that the facade takes it as it is.
//
// The app that embeds the SDK needs the App Attest capability (the
// `com.apple.developer.devicecheck.appattest-environment` entitlement). Without it the service
// refuses to make a key, which reads as "no evidence" below, never as an error of the login.

/// Why App Attest did not give what was asked. Only what the SDK acts on is told apart.
package enum AppAttestFailure: Error, Sendable, Equatable {
    /// This device, build or entitlement cannot use App Attest (a simulator, an app without the
    /// capability, an app extension).
    case unsupported

    /// Apple's service could not be reached: nothing is wrong with the key, and asking again later may work.
    case unavailable

    /// App Attest does not know this key: it was made by another install (a Keychain item that
    /// outlived its app, a restore onto another device), or it was already attested.
    case invalidKey

    case other
}

/// `DCAppAttestService`, as far as the SDK uses it, so that the logic around it is testable where
/// App Attest does not run (a macOS host, a simulator).
///
/// The `clientDataHash` is the one `NativeAttestation.clientDataHash` makes. Implementations throw
/// [`AppAttestFailure`] and nothing else.
package protocol AppAttestService: Sendable {
    var isSupported: Bool { get }
    func generateKey() async throws -> String
    func attestKey(_ keyId: String, clientDataHash: Data) async throws -> Data
    func generateAssertion(_ keyId: String, clientDataHash: Data) async throws -> Data
}

/// The real service. Every `DCError` is read as one of [`AppAttestFailure`]; anything that is not a
/// `DCError` is `.other`, with no detail kept: a message from the framework has no use for an app and
/// the key id is not for a log.
package struct DeviceCheckAppAttestService: AppAttestService {
    package init() {}

    package var isSupported: Bool { DCAppAttestService.shared.isSupported }

    package func generateKey() async throws -> String {
        do { return try await DCAppAttestService.shared.generateKey() } catch { throw Self.failure(of: error) }
    }

    package func attestKey(_ keyId: String, clientDataHash: Data) async throws -> Data {
        do { return try await DCAppAttestService.shared.attestKey(keyId, clientDataHash: clientDataHash) } catch {
            throw Self.failure(of: error)
        }
    }

    package func generateAssertion(_ keyId: String, clientDataHash: Data) async throws -> Data {
        do { return try await DCAppAttestService.shared.generateAssertion(keyId, clientDataHash: clientDataHash) } catch {
            throw Self.failure(of: error)
        }
    }

    static func failure(of error: Error) -> Error {
        // A cancelled caller is not a failure of App Attest, and is never turned into one.
        if error is CancellationError { return error }
        guard let dc = error as? DCError else { return AppAttestFailure.other }
        switch dc.code {
        case .featureUnsupported: return AppAttestFailure.unsupported
        case .serverUnavailable: return AppAttestFailure.unavailable
        case .invalidKey, .invalidInput: return AppAttestFailure.invalidKey
        default: return AppAttestFailure.other
        }
    }
}

// MARK: - The key this install holds

/// The App Attest key of this install, and whether it has been attested. The key id is public (a hash
/// of a public key), but it names this install to edge, so it lives where the refresh token does.
package struct AppAttestKeyState: Sendable, Equatable, Codable {
    package let keyId: String
    package let attested: Bool

    package init(keyId: String, attested: Bool) {
        self.keyId = keyId
        self.attested = attested
    }
}

package protocol AppAttestKeyStore: Sendable {
    func load() async throws -> AppAttestKeyState?
    func save(_ state: AppAttestKeyState) async throws
    func clear() async throws
}

/// The key state in the Keychain, `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` and never
/// synchronised: an App Attest key is bound to this device's Secure Enclave, so an item that reached
/// another device would name a key that device does not have.
///
/// Survives logout, unlike the DPoP key: the key says what the install is, not who is signed in, and
/// App Attest attests a key once, so dropping it at every sign-out would attest a new one at every
/// sign-in. It does not survive a reinstall where the facade wires `FirstLaunchGuard` (which deletes every item
/// of the client, and is inert in an app extension and not built for a configured access group), and a key id
/// that does outlive its app is one App Attest no longer knows, which the evidence source reads from
/// `.invalidKey` and replaces: that is the safety net, not the guard.
package actor KeychainAppAttestKeyStore: AppAttestKeyStore {
    private let item: KeychainItem
    private let firstLaunch: FirstLaunchGuard?

    package init(storageKey: String, accessGroup: String? = nil, firstLaunch: FirstLaunchGuard? = nil, logger: (any OAuthLogger)? = nil) {
        self.firstLaunch = firstLaunch
        item = KeychainItem(
            service: KeychainItem.service(forStorageKey: storageKey), account: "app-attest-key",
            accessibility: .afterFirstUnlock, accessGroup: accessGroup, logger: logger
        )
    }

    package func load() async throws -> AppAttestKeyState? {
        try firstLaunch?.ensure()
        guard let data = try item.read() else { return nil }
        // A record this version cannot read is no record: a new key is made rather than failing every launch.
        guard let state = try? JSONDecoder().decode(AppAttestKeyState.self, from: data) else {
            try item.delete()
            return nil
        }
        return state
    }

    package func save(_ state: AppAttestKeyState) async throws {
        try firstLaunch?.ensure()
        try item.write(try JSONEncoder().encode(state))
    }

    package func clear() async throws {
        try firstLaunch?.ensure()
        try item.delete()
    }
}

package actor InMemoryAppAttestKeyStore: AppAttestKeyStore {
    private var state: AppAttestKeyState?

    package init(_ state: AppAttestKeyState? = nil) { self.state = state }

    package func load() async throws -> AppAttestKeyState? { state }
    package func save(_ state: AppAttestKeyState) async throws { self.state = state }
    package func clear() async throws { state = nil }
}

// MARK: - The evidence

/// The evidence an iOS app gives edge on `/native/start`: the first request of a key carries its
/// attestation, every later one an assertion, each made over the hash of that request
/// (`NativeAttestation.clientDataHash`).
///
/// **Evidence, never a permission.** What App Attest cannot give is no evidence and no error: a device
/// without it, Apple's service out of reach, a failure it does not explain -- each returns an empty list,
/// and edge's policy for the client decides whether a request without any is acceptable. A key App Attest
/// does not know is dropped and a new one is made and attested in the same call, once. Only a failure of
/// the SDK's own store is thrown, as the other stores throw it (a locked Keychain is `unlockRequired`): it is
/// the Keychain the refresh token lives in, so a login that cannot use it fails anyway, whatever edge's
/// policy for the client is. A cancelled caller stays cancelled.
///
/// The values go into an `application/x-www-form-urlencoded` body, and base64 has `+`, `/` and `=`: the
/// facade percent-encodes them, as it does every field.
///
/// An attestation object is made for one request and App Attest attests a key once, so it is never
/// handed out twice: the state is saved as attested before the object is returned. If the request
/// then fails before edge sees it, the next assertion is for a key edge has not been shown, which edge
/// refuses as `this key has not been attested: send the attestation object`; the facade calls
/// [`discardKey`] on that answer and the next request attests a new key.
///
/// Calls are served one at a time, in order, **across their suspension points**: an actor alone does not do
/// that (it is reentrant at every `await`), and two overlapping calls would each make a key, attest the
/// same one twice, or clear what the other just saved. It does not order the requests that carry the
/// assertions: edge accepts an assertion only if its counter is greater than the last, so two starts in
/// flight at once can still lose one to the other. A login is single-flight (`AuthorizationFlow` joins
/// equal calls), so this does not arise from the SDK's own use.
package actor AppAttestEvidence: NativeStartAttestation {
    private let service: any AppAttestService
    private let store: any AppAttestKeyStore
    private let logger: (any OAuthLogger)?

    private var busy = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    package init(service: any AppAttestService, store: any AppAttestKeyStore, logger: (any OAuthLogger)? = nil) {
        self.service = service
        self.store = store
        self.logger = logger
    }

    private func acquire() async {
        if busy {
            await withCheckedContinuation { waiters.append($0) }
        } else {
            busy = true
        }
    }

    private func release() {
        if waiters.isEmpty {
            busy = false
        } else {
            waiters.removeFirst().resume()
        }
    }

    package func fields(clientId: String, jkt: String, jti: String) async throws -> [NativeStartField] {
        guard service.isSupported else { return [] }
        await acquire()
        defer { release() }
        let hash = NativeAttestation.clientDataHash(clientId: clientId, jkt: jkt, jti: jti)
        // A key App Attest does not know is often our own state's doing (the process died between the attestation
        // and the save, or an item outlived its app), so a new key is made and attested in the same call, once.
        for attempt in 0..<2 {
            do {
                return try await evidence(hash: hash)
            } catch let failure as AppAttestFailure {
                // The framework's own way of surfacing a cancelled caller is not known to be a `CancellationError`.
                try Task.checkCancellation()
                if failure == .invalidKey {
                    logger?.warn("App Attest does not know this install's key")
                    try await store.clear()
                    if attempt == 0 { continue }
                } else {
                    logger?.info("App Attest gave no evidence for this request: \(failure)")
                }
                return []
            }
        }
        return []
    }

    private func evidence(hash: Data) async throws -> [NativeStartField] {
        var state = try await store.load()
        if state == nil {
            let keyId = try await service.generateKey()
            state = AppAttestKeyState(keyId: keyId, attested: false)
            try await store.save(state!)
        }
        let key = state!
        if key.attested {
            let assertion = try await service.generateAssertion(key.keyId, clientDataHash: hash)
            return NativeAttestation.fields(keyId: key.keyId, assertion: assertion)
        }
        let object = try await service.attestKey(key.keyId, clientDataHash: hash)
        // Saved as attested before the object is handed out: an object is never handed out twice.
        try await store.save(AppAttestKeyState(keyId: key.keyId, attested: true))
        return NativeAttestation.fields(keyId: key.keyId, attestationObject: object)
    }

    /// Forgets the key, so the next request makes and attests a new one: what the facade does when edge
    /// answers that the key has not been attested, or refuses an attestation.
    package func discardKey() async throws {
        await acquire()
        defer { release() }
        try await store.clear()
    }
}
