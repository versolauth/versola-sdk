import CryptoKit
import Foundation
import Security


/// Where a DPoP key's tier came from, read back from the key that was loaded, never assumed
/// (`security.md`: "do not report a tier you did not read back").
public struct KeyAttestation: Sendable, Equatable {
    public enum Tier: String, Sendable {
        /// Generated in and never leaving the Secure Enclave.
        case secureEnclave
        /// A CryptoKit key held in the Keychain: a device without a Secure Enclave, or a simulator.
        case software
    }

    public let tier: Tier

    public init(tier: Tier) {
        self.tier = tier
    }
}

/// Where a DPoP key's persisted representation lives. Synchronous on purpose: the key actor
/// must not suspend between "is there one" and "store the new one", or two callers racing
/// through actor reentrancy would each generate a key.
package protocol DpopKeyStore: Sendable {
    func load() throws -> Data?
    func save(_ data: Data) throws
    func delete() throws
}

/// The DPoP key's persistent form in the Keychain: service "versola.oauth.<storageKey>",
/// account "dpop-key", `AfterFirstUnlockThisDeviceOnly` and not synchronizable. Never gated on
/// user presence: a gated key breaks the background refresh (#1 section 4).
package struct KeychainDpopKeyStore: DpopKeyStore {
    private let item: KeychainItem
    private let firstLaunch: FirstLaunchGuard?

    package init(storageKey: String, accessGroup: String? = nil, firstLaunch: FirstLaunchGuard? = nil) {
        self.firstLaunch = firstLaunch
        item = KeychainItem(
            service: KeychainItem.service(forStorageKey: storageKey), account: "dpop-key",
            accessibility: .afterFirstUnlock, accessGroup: accessGroup
        )
    }

    package func load() throws -> Data? {
        try firstLaunch?.ensure()
        return try item.read()
    }
    package func save(_ data: Data) throws {
        try firstLaunch?.ensure()
        try item.write(data)
    }
    package func delete() throws {
        try firstLaunch?.ensure()
        try item.delete()
    }
}

/// An EC P-256 key for DPoP proofs: a `SecureEnclave.P256` key where the device has one, a
/// CryptoKit software key otherwise, and which of the two it is is a fact the app can ask for
/// (`attestation()`), not one the SDK hides.
///
/// Not user-gated, for the reason Android's key is not: a proof is signed on every request,
/// and a prompt per request is not an option. Persisted as a Secure Enclave `dataRepresentation`
/// (an encrypted blob only this device's enclave can use) or the software key's raw bytes,
/// each behind a one-byte tag so a load reads back which one it is rather than guessing from
/// the length. Destroyed on logout.
package actor SecureEnclaveDpopKey: DpopSigningKey {
    private enum Tag: UInt8 {
        case secureEnclave = 1
        case software = 2
    }

    private enum Loaded {
        case enclave(SecureEnclave.P256.Signing.PrivateKey)
        case software(P256.Signing.PrivateKey)

        var attestation: KeyAttestation {
            switch self {
            case .enclave: return KeyAttestation(tier: .secureEnclave)
            case .software: return KeyAttestation(tier: .software)
            }
        }

        var publicKey: P256.Signing.PublicKey {
            switch self {
            case .enclave(let key): return key.publicKey
            case .software(let key): return key.publicKey
            }
        }

        func signature(for data: Data) throws -> P256.Signing.ECDSASignature {
            switch self {
            case .enclave(let key): return try key.signature(for: data)
            case .software(let key): return try key.signature(for: data)
            }
        }
    }

    private let store: any DpopKeyStore
    private let requireHardware: Bool
    private let logger: (any OAuthLogger)?
    private let enclaveAvailable: Bool
    private let makeEnclaveKey: @Sendable () throws -> SecureEnclave.P256.Signing.PrivateKey
    private var loaded: Loaded?

    /// - Parameters:
    ///   - requireHardware: throw `hardwareBindingUnavailable` instead of falling back to a
    ///     software key (`TokenBinding.dpop` with a hardware requirement).
    ///   - logger: receives the one warning a software-tier key deserves.
    package init(storageKey: String, accessGroup: String? = nil, requireHardware: Bool = false, logger: (any OAuthLogger)? = nil, firstLaunch: FirstLaunchGuard? = nil) {
        self.init(
            store: KeychainDpopKeyStore(storageKey: storageKey, accessGroup: accessGroup, firstLaunch: firstLaunch), requireHardware: requireHardware,
            logger: logger, secureEnclaveAvailable: SecureEnclave.isAvailable
        )
    }

    /// For a store of the caller's own, and for tests, which also decide whether the enclave
    /// counts as present (a Mac host may report one it cannot use unsigned) and what making a key
    /// does (`makeEnclaveKey`, which a test makes fail the way a locked device does).
    package init(
        store: any DpopKeyStore, requireHardware: Bool = false, logger: (any OAuthLogger)? = nil,
        secureEnclaveAvailable: Bool = SecureEnclave.isAvailable,
        makeEnclaveKey: @escaping @Sendable () throws -> SecureEnclave.P256.Signing.PrivateKey = SecureEnclaveDpopKey.newEnclaveKey
    ) {
        self.store = store
        self.requireHardware = requireHardware
        self.logger = logger
        self.enclaveAvailable = secureEnclaveAvailable
        self.makeEnclaveKey = makeEnclaveKey
    }

    /// The access control the enclave key is created with, spelled out rather than left to
    /// CryptoKit's default: `AfterFirstUnlockThisDeviceOnly`, no flags (so no user presence, and
    /// no biometry binding that an enrolment change would invalidate). Signing then works while
    /// the device is locked, which a push-triggered or `BGAppRefreshTask` refresh needs, and the
    /// key never leaves the device. This is what Apple documents as the initializer's default, and
    /// the shipped CryptoKit interface of the SDK this was built against declares the same, so
    /// keys made before this was explicit have the same access control and need no migration.
    static func enclaveAccessControl() throws -> SecAccessControl {
        var failure: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, [], &failure) else {
            failure?.release()
            throw OAuthError.configuration(.hardwareBindingUnavailable(detail: "the Secure Enclave access control could not be created"))
        }
        return access
    }

    @Sendable static func newEnclaveKey() throws -> SecureEnclave.P256.Signing.PrivateKey {
        try SecureEnclave.P256.Signing.PrivateKey(accessControl: enclaveAccessControl())
    }

    /// The tier of the key in use, generating the key first if there is none.
    package func attestation() async throws -> KeyAttestation { try key().attestation }

    /// The package key as a JWK: `kty`, `crv`, `x`, `y` and nothing else (RFC 9449 section 4.1
    /// puts it in the proof's header, where extra members would be noise and `d` a catastrophe).
    package func publicJwk() async throws -> JsonWebKey {
        // x9.63 is 0x04 || X || Y, 32 bytes each.
        let point = try key().publicKey.x963Representation
        return JsonWebKey(
            kty: "EC", crv: "P-256", x: Base64URLEncoder.encode(point.subdata(in: 1..<33)),
            y: Base64URLEncoder.encode(point.subdata(in: 33..<65))
        )
    }

    /// `R || S`, 64 bytes: what JWS ES256 wants, and what CryptoKit's `rawRepresentation`
    /// already is, so Android's DER conversion has no counterpart here.
    package func sign(_ data: Data) async throws -> Data {
        let key = try key()
        do {
            return try key.signature(for: data).rawRepresentation
        } catch {
            // A raw CryptoKit error would reach the app as an untyped failure it cannot act on
            // (`spec/errors.md`): a locked device is `unlockRequired`, the key intact.
            if case .enclave = key { throw Self.typed(signingError: error, store: store) }
            throw error
        }
    }

    /// What a failed enclave signature means to the app. The enclave key is usable once the
    /// device has been unlocked since boot (`AfterFirstUnlock`), so the failure that matters is a
    /// refusal before that or while the store is out of reach: `unlockRequired`, never a reason to
    /// destroy the key under a live grant. CryptoKit's error shape for that refusal is not
    /// documented, so when the status cannot be read off it the Keychain is asked directly: the
    /// key's own store item has the same class, and says plainly whether it is reachable.
    /// Anything else is reported as the hardware being unable to sign, which names no key material.
    static func typed(signingError error: Error, store: any DpopKeyStore) -> OAuthError {
        if let status = KeychainFailure.status(of: error), KeychainFailure.isUnavailableForNow(status) {
            return .recoverable(.unlockRequired)
        }
        if case .recoverable(.unlockRequired)? = (error as? OAuthError) { return .recoverable(.unlockRequired) }
        do { _ = try store.load() } catch let probed as OAuthError {
            if case .recoverable(.unlockRequired) = probed { return probed }
        } catch {}
        return .configuration(.hardwareBindingUnavailable(detail: "the Secure Enclave could not sign the proof"))
    }

    /// Deletes the persisted key and forgets it: the next proof is signed by a freshly
    /// generated one with a different thumbprint. Logout does this, so one grant is bound to one
    /// device-installation and the next user of a shared device starts with a key of their own.
    package func destroy() async throws {
        try store.delete()
        loaded = nil
    }

    // MARK: Loading and generation

    private func key() throws -> Loaded {
        if let loaded { return loaded }
        let key = try load() ?? generate()
        // Checked on the key that came back, loaded or fresh, so a persisted software key is
        // refused under `requireHardware` as well.
        if requireHardware, case .software = key {
            throw OAuthError.configuration(.hardwareBindingUnavailable(detail: "this device produced a software-backed DPoP key"))
        }
        if case .software = key {
            logger?.warn("DPoP key is software-backed: this device has no Secure Enclave. Require hardware binding to refuse this.")
        }
        loaded = key
        return key
    }

    private func load() throws -> Loaded? {
        guard let stored = try store.load() else { return nil }
        // A blob that cannot be loaded fails closed: silently minting a new key here would
        // change the thumbprint under a live grant. The caller destroys the key to recover.
        guard let first = stored.first, let tag = Tag(rawValue: first) else {
            throw OAuthError.configuration(.hardwareBindingUnavailable(detail: "the stored DPoP key is not readable"))
        }
        let body = stored.dropFirst()
        do {
            switch tag {
            case .secureEnclave:
                guard enclaveAvailable else {
                    throw OAuthError.configuration(.hardwareBindingUnavailable(detail: "the stored DPoP key needs a Secure Enclave"))
                }
                return .enclave(try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: Data(body)))
            case .software:
                return .software(try P256.Signing.PrivateKey(rawRepresentation: body))
            }
        } catch let error as OAuthError {
            throw error
        } catch {
            // A key the enclave cannot open because the device is locked is not a key that is
            // unreadable: reporting it as such would send the app to destroy it.
            if let status = KeychainFailure.status(of: error), KeychainFailure.isUnavailableForNow(status) {
                throw OAuthError.recoverable(.unlockRequired)
            }
            throw OAuthError.configuration(.hardwareBindingUnavailable(detail: "the stored DPoP key is not readable"))
        }
    }

    private func generate() throws -> Loaded {
        if enclaveAvailable {
            // Runtime fall-through, as Android's StrongBox to TEE: a device that reports an
            // enclave can still refuse a key (an unsigned test host), and what happens then is
            // the app's `requireHardware`, not a crash.
            do {
                let enclave = try makeEnclaveKey()
                try store.save(Data([Tag.secureEnclave.rawValue]) + enclave.dataRepresentation)
                return .enclave(enclave)
            } catch {
                // A device that is merely locked is not one that refuses keys: falling through
                // here would persist a software key for good because of a passing condition.
                if let status = KeychainFailure.status(of: error), KeychainFailure.isUnavailableForNow(status) {
                    throw OAuthError.recoverable(.unlockRequired)
                }
                // A failure to persist the new key is the store's, not the enclave's.
                if error is OAuthError { throw error }
            }
            logger?.warn("the Secure Enclave refused to generate a key")
        }
        if requireHardware {
            throw OAuthError.configuration(.hardwareBindingUnavailable(detail: "no Secure Enclave is available on this device"))
        }
        let software = P256.Signing.PrivateKey()
        try store.save(Data([Tag.software.rawValue]) + software.rawRepresentation)
        return .software(software)
    }
}
