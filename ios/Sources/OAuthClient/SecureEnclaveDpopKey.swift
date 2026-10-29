import CryptoKit
import Foundation


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
public protocol DpopKeyStore: Sendable {
    func load() throws -> Data?
    func save(_ data: Data) throws
    func delete() throws
}

/// The DPoP key's persistent form in the Keychain: service "versola.oauth.<storageKey>",
/// account "dpop-key", `AfterFirstUnlockThisDeviceOnly` and not synchronizable. Never gated on
/// user presence: a gated key breaks the background refresh (#1 section 4).
public struct KeychainDpopKeyStore: DpopKeyStore {
    private let item: KeychainItem

    public init(storageKey: String, accessGroup: String? = nil) {
        item = KeychainItem(
            service: KeychainItem.service(forStorageKey: storageKey), account: "dpop-key",
            accessibility: .afterFirstUnlock, accessGroup: accessGroup
        )
    }

    public func load() throws -> Data? { try item.read() }
    public func save(_ data: Data) throws { try item.write(data) }
    public func delete() throws { try item.delete() }
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
public actor SecureEnclaveDpopKey: DpopSigningKey {
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
    private var loaded: Loaded?

    /// - Parameters:
    ///   - requireHardware: throw `hardwareBindingUnavailable` instead of falling back to a
    ///     software key (`TokenBinding.dpop` with a hardware requirement).
    ///   - logger: receives the one warning a software-tier key deserves.
    public init(storageKey: String, accessGroup: String? = nil, requireHardware: Bool = false, logger: (any OAuthLogger)? = nil) {
        self.init(
            store: KeychainDpopKeyStore(storageKey: storageKey, accessGroup: accessGroup), requireHardware: requireHardware,
            logger: logger, secureEnclaveAvailable: SecureEnclave.isAvailable
        )
    }

    /// For a store of the caller's own, and for tests, which also decide whether the enclave
    /// counts as present (a Mac host may report one it cannot use unsigned).
    public init(
        store: any DpopKeyStore, requireHardware: Bool = false, logger: (any OAuthLogger)? = nil,
        secureEnclaveAvailable: Bool = SecureEnclave.isAvailable
    ) {
        self.store = store
        self.requireHardware = requireHardware
        self.logger = logger
        self.enclaveAvailable = secureEnclaveAvailable
    }

    /// The tier of the key in use, generating the key first if there is none.
    public func attestation() async throws -> KeyAttestation { try key().attestation }

    /// The public key as a JWK: `kty`, `crv`, `x`, `y` and nothing else (RFC 9449 section 4.1
    /// puts it in the proof's header, where extra members would be noise and `d` a catastrophe).
    public func publicJwk() async throws -> JsonWebKey {
        // x9.63 is 0x04 || X || Y, 32 bytes each.
        let point = try key().publicKey.x963Representation
        return JsonWebKey(
            kty: "EC", crv: "P-256", x: Base64URLEncoder.encode(point.subdata(in: 1..<33)),
            y: Base64URLEncoder.encode(point.subdata(in: 33..<65))
        )
    }

    /// `R || S`, 64 bytes: what JWS ES256 wants, and what CryptoKit's `rawRepresentation`
    /// already is, so Android's DER conversion has no counterpart here.
    public func sign(_ data: Data) async throws -> Data {
        try key().signature(for: data).rawRepresentation
    }

    /// Deletes the persisted key and forgets it: the next proof is signed by a freshly
    /// generated one with a different thumbprint. Logout does this, so one grant is bound to one
    /// device-installation and the next user of a shared device starts with a key of their own.
    public func destroy() async throws {
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
            throw OAuthError.configuration(.hardwareBindingUnavailable(detail: "the stored DPoP key is not readable"))
        }
    }

    private func generate() throws -> Loaded {
        if enclaveAvailable {
            // Runtime fall-through, as Android's StrongBox to TEE: a device that reports an
            // enclave can still refuse a key (an unsigned test host), and what happens then is
            // the app's `requireHardware`, not a crash.
            if let enclave = try? SecureEnclave.P256.Signing.PrivateKey() {
                try store.save(Data([Tag.secureEnclave.rawValue]) + enclave.dataRepresentation)
                return .enclave(enclave)
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
