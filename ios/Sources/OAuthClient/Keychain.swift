import CryptoKit
import Foundation
import Security

// The durable half of a session lives in the Keychain: generic-password items under one
// service per client ("versola.oauth.<storageKey>"), one account per item. See
// `spec/state-machine.md`, persistence summary, and `.claude/rules/security.md`.

/// How reachable an item is while the device is locked.
enum KeychainAccessibility: Sendable, Equatable {
    /// `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`: a background refresh works, the item
    /// never leaves the device (no backup restore, no iCloud Keychain).
    case afterFirstUnlock
    /// `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`: `UnlockPolicy.onAppUnlock`.
    case whenUnlocked

    init(_ policy: UnlockPolicy) {
        switch policy {
        case .none: self = .afterFirstUnlock
        case .onAppUnlock: self = .whenUnlocked
        }
    }

    var attribute: CFString {
        switch self {
        case .afterFirstUnlock: return kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        case .whenUnlocked: return kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        }
    }
}

/// Which Keychain and Secure Enclave failures are the store being out of reach, not broken.
enum KeychainFailure {
    /// The statuses of a store that cannot be used right now and will be later, none of which
    /// says anything about the item:
    /// - `errSecInteractionNotAllowed` (-25308): the device is locked, or has not been unlocked
    ///   since boot (an `AfterFirstUnlock` item before that first unlock, a `WhenUnlocked` one
    ///   while locked).
    /// - `errSecNotAvailable` (-25291): the Keychain is not available yet, which is early boot and
    ///   the same wait.
    /// - `errSecAuthFailed` (-25293): authentication to the store failed or was withheld, which on a
    ///   locked device is the lock again; the app unlocks and retries.
    /// Everything else (a missing entitlement, a malformed query, a corrupt item) is permanent and
    /// stays `invalidConfiguration`: signing the user out for the first and calling the second
    /// "retry later" would each be the wrong answer.
    static func isUnavailableForNow(_ status: OSStatus) -> Bool {
        status == errSecInteractionNotAllowed || status == errSecNotAvailable || status == errSecAuthFailed
    }

    /// The `OSStatus` inside an error that crossed CryptoKit or Security, when it carries one.
    /// CryptoKit reports the Secure Enclave's refusals as `underlyingCoreCryptoError`; Security
    /// bridged errors are an `NSError` in the OSStatus domain.
    static func status(of error: Error) -> OSStatus? {
        if let crypto = error as? CryptoKitError, case .underlyingCoreCryptoError(let status) = crypto { return status }
        let bridged = error as NSError
        if bridged.domain == NSOSStatusErrorDomain { return OSStatus(truncatingIfNeeded: bridged.code) }
        return nil
    }
}

/// One generic-password item, and the only code that talks to `SecItem*`. Value type with no
/// state: the stores serialise their own calls as actors.
struct KeychainItem: Sendable {
    let service: String
    let account: String
    let accessibility: KeychainAccessibility
    let accessGroup: String?

    init(service: String, account: String, accessibility: KeychainAccessibility, accessGroup: String? = nil) {
        self.service = service
        self.account = account
        self.accessibility = accessibility
        self.accessGroup = accessGroup
    }

    static func service(forStorageKey storageKey: String) -> String { "versola.oauth.\(storageKey)" }

    /// The statuses that mean something to the SDK; the code never reaches for the data of a
    /// failure, and the detail is the number only. A status that says the store is out of reach
    /// for now (`KeychainFailure.isUnavailableForNow`) is `unlockRequired`, the grant intact; any
    /// other is a fault no retry changes.
    static func error(for status: OSStatus) -> OAuthError {
        if KeychainFailure.isUnavailableForNow(status) { return .recoverable(.unlockRequired) }
        return .configuration(.invalidConfiguration(detail: "keychain error \(status)"))
    }

    private var query: [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            // Never iCloud Keychain, and the same semantics on a macOS test host as on iOS.
            kSecAttrSynchronizable as String: false,
            kSecUseDataProtectionKeychain as String: true,
        ]
        if let accessGroup { query[kSecAttrAccessGroup as String] = accessGroup }
        return query
    }

    /// The item's data, or nil when there is none. Locked device: `unlockRequired`.
    func read() throws -> Data? {
        var query = self.query
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        switch status {
        case errSecSuccess: return result as? Data
        case errSecItemNotFound: return nil
        default: throw Self.error(for: status)
        }
    }

    /// Whether the item exists, from its attributes alone: no data is requested, so a locked
    /// device is not asked for anything it would have to unlock.
    func exists() throws -> Bool {
        var query = self.query
        query[kSecReturnAttributes as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        switch status {
        case errSecSuccess: return true
        case errSecItemNotFound: return false
        default: throw Self.error(for: status)
        }
    }

    /// Update when the item exists, add otherwise. Never delete-then-add: a crash between the
    /// two would lose the credential, and the new value must be in place before the old is gone.
    func write(_ data: Data) throws {
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: accessibility.attribute,
        ]
        var status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            status = SecItemAdd(query.merging(attributes) { $1 } as CFDictionary, nil)
            // Another writer added it between the update and the add: update once more.
            if status == errSecDuplicateItem {
                status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
            }
        }
        if status != errSecSuccess { throw Self.error(for: status) }
    }

    func delete() throws {
        let status = SecItemDelete(query as CFDictionary)
        if status != errSecSuccess && status != errSecItemNotFound { throw Self.error(for: status) }
    }
}

// MARK: - Credential store

/// The refresh token, the raw ID token and the rotation slot in the Keychain. Three items under
/// one service, `AfterFirstUnlockThisDeviceOnly` (or `WhenUnlockedThisDeviceOnly` under
/// `UnlockPolicy.onAppUnlock`), never synchronizable.
package actor KeychainCredentialStore: CredentialStore {
    private let refreshItem: KeychainItem
    private let idTokenItem: KeychainItem
    private let rotationItem: KeychainItem

    package init(storageKey: String, unlockPolicy: UnlockPolicy, accessGroup: String? = nil) {
        let service = KeychainItem.service(forStorageKey: storageKey)
        let accessibility = KeychainAccessibility(unlockPolicy)
        refreshItem = KeychainItem(service: service, account: "refresh-token", accessibility: accessibility, accessGroup: accessGroup)
        idTokenItem = KeychainItem(service: service, account: "id-token", accessibility: accessibility, accessGroup: accessGroup)
        rotationItem = KeychainItem(service: service, account: "pending-rotation", accessibility: accessibility, accessGroup: accessGroup)
    }

    /// Attributes only: a cold start must not turn into an unlock prompt under `onAppUnlock`.
    package func hasGrant() async throws -> Bool { try refreshItem.exists() }

    package func refreshToken() async throws -> String? { try refreshItem.read().flatMap { String(data: $0, encoding: .utf8) } }

    package func rawIdToken() async throws -> String? { try idTokenItem.read().flatMap { String(data: $0, encoding: .utf8) } }

    /// The refresh token first, then the ID token: if the process dies between the two the
    /// grant is the new one, which is the part that cannot be recovered.
    package func save(refreshToken: String, rawIdToken: String?) async throws {
        try refreshItem.write(Data(refreshToken.utf8))
        if let rawIdToken {
            try idTokenItem.write(Data(rawIdToken.utf8))
        } else {
            // A stale ID token must not outlive the grant it belonged to (`id_token_hint`).
            try idTokenItem.delete()
        }
    }

    package func savePendingRotation(_ idempotencyKey: String?) async throws {
        if let idempotencyKey {
            try rotationItem.write(Data(idempotencyKey.utf8))
        } else {
            try rotationItem.delete()
        }
    }

    package func pendingRotation() async throws -> String? { try rotationItem.read().flatMap { String(data: $0, encoding: .utf8) } }

    package func clear() async throws {
        try refreshItem.delete()
        try idTokenItem.delete()
        try rotationItem.delete()
    }
}

// MARK: - Pending authorization

/// The pending authorization request in the Keychain, as JSON (the code verifier is in it, so
/// it is a credential and gets the same class as the refresh token).
package actor KeychainPendingAuthorizationStore: PendingAuthorizationStore {
    private let item: KeychainItem

    package init(storageKey: String, unlockPolicy: UnlockPolicy, accessGroup: String? = nil) {
        item = KeychainItem(
            service: KeychainItem.service(forStorageKey: storageKey), account: "pending-authorization",
            accessibility: KeychainAccessibility(unlockPolicy), accessGroup: accessGroup
        )
    }

    package func save(_ request: PendingAuthorizationRequest) async throws {
        try item.write(try PendingRequestCoding.encode(request))
    }

    package func load() async throws -> PendingAuthorizationRequest? {
        guard let data = try item.read() else { return nil }
        // A record this version cannot read is no record: the flow starts over rather than
        // failing every launch. It is removed so the next save is not an update of garbage.
        guard let request = PendingRequestCoding.decode(data) else {
            try item.delete()
            return nil
        }
        return request
    }

    package func clear() async throws { try item.delete() }
}

enum PendingRequestCoding {
    static func encode(_ request: PendingAuthorizationRequest) throws -> Data {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        return try encoder.encode(request)
    }

    static func decode(_ data: Data) -> PendingAuthorizationRequest? {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try? decoder.decode(PendingAuthorizationRequest.self, from: data)
    }
}

// MARK: - In-memory stores

/// A `CredentialStore` in memory. NEVER SECURE and never shipped in an app: nothing is encrypted,
/// nothing survives the process. It exists for unit tests and for the conformance driver.
package actor InMemoryCredentialStore: CredentialStore {
    private var refresh: String?
    private var idToken: String?
    private var rotation: String?

    package init() {}

    package func hasGrant() async throws -> Bool { refresh != nil }
    package func refreshToken() async throws -> String? { refresh }
    package func rawIdToken() async throws -> String? { idToken }

    package func save(refreshToken: String, rawIdToken: String?) async throws {
        refresh = refreshToken
        idToken = rawIdToken
    }

    package func savePendingRotation(_ idempotencyKey: String?) async throws { rotation = idempotencyKey }
    package func pendingRotation() async throws -> String? { rotation }

    package func clear() async throws {
        refresh = nil
        idToken = nil
        rotation = nil
    }
}

/// A `PendingAuthorizationStore` in memory. NEVER SECURE and never shipped in an app: see
/// `InMemoryCredentialStore`.
package actor InMemoryPendingAuthorizationStore: PendingAuthorizationStore {
    private var request: PendingAuthorizationRequest?

    package init() {}

    package func save(_ request: PendingAuthorizationRequest) async throws { self.request = request }
    package func load() async throws -> PendingAuthorizationRequest? { request }
    package func clear() async throws { request = nil }
}
