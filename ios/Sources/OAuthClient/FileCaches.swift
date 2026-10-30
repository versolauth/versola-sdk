import Foundation

/// One JSON file in a directory the caller owns. Public keys and discovery documents are not
/// secrets, so the file is unencrypted (`spec/oauth-sdk-api.md` section 14), but it is excluded
/// from backup: a cache restored onto another device would only be stale.
struct JSONFile<Value: Codable & Sendable>: Sendable {
    let url: URL

    init(directory: URL, name: String) {
        url = directory.appendingPathComponent(name, isDirectory: false)
    }

    /// Nil when the file is absent, unreadable or corrupt; a corrupt file is deleted so the
    /// next save does not start from garbage. Never throws: a cache that cannot be read is a
    /// cache miss, not a failure of the operation that wanted it.
    func load() -> Value? {
        guard let data = try? Data(contentsOf: url) else { return nil }
        guard let value = try? JSONDecoder().decode(Value.self, from: data) else {
            try? FileManager.default.removeItem(at: url)
            return nil
        }
        return value
    }

    func save(_ value: Value) throws {
        let directory = url.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        var directoryURL = directory
        try? directoryURL.setResourceValues(values)
        try JSONEncoder().encode(value).write(to: url, options: .atomic)
        var fileURL = url
        try? fileURL.setResourceValues(values)
    }

    func modificationDate() -> Date? {
        (try? FileManager.default.attributesOfItem(atPath: url.path))?[.modificationDate] as? Date
    }
}

/// A document and how long it was to be trusted when it was saved (`CacheLifetime`). A file of
/// the earlier format (the bare document) does not decode as this, is dropped as corrupt, and the
/// document is fetched once more.
struct Stored<Value: Codable & Sendable>: Codable, Sendable {
    let value: Value
    let lifetime: TimeInterval?
}

/// The discovered metadata on disk. The client points it at
/// `Application Support/versola-oauth/<storageKey>/`. It survives logout on purpose: a re-login
/// should not need a round trip to the discovery document.
package actor FileProviderMetadataCache: ProviderMetadataCache {
    private let file: JSONFile<Stored<ProviderMetadata>>

    package init(directory: URL) {
        file = JSONFile(directory: directory, name: "provider-metadata.json")
    }

    package func load() async throws -> ProviderMetadata? { file.load()?.value }
    package func save(_ metadata: ProviderMetadata) async throws { try await save(metadata, lifetime: nil) }
    package func save(_ metadata: ProviderMetadata, lifetime: TimeInterval?) async throws {
        try file.save(Stored(value: metadata, lifetime: lifetime))
    }

    /// When the document was last written; with the lifetime it was saved with, the client
    /// refetches a document older than that (`spec/oauth-sdk-api.md` section 4).
    package func savedAt() async throws -> Date? { file.modificationDate() }
    package func lifetime() async throws -> TimeInterval? { file.load()?.lifetime }
}

/// The provider's key set on disk, unencrypted (package keys), expiring like the metadata.
package actor FileJwksCache: JwksCache {
    private let file: JSONFile<Stored<JsonWebKeySet>>

    package init(directory: URL) {
        file = JSONFile(directory: directory, name: "jwks.json")
    }

    package func load() async throws -> JsonWebKeySet? { file.load()?.value }
    package func save(_ set: JsonWebKeySet) async throws { try await save(set, lifetime: nil) }
    package func save(_ set: JsonWebKeySet, lifetime: TimeInterval?) async throws {
        try file.save(Stored(value: set, lifetime: lifetime))
    }
    package func savedAt() async throws -> Date? { file.modificationDate() }
    package func lifetime() async throws -> TimeInterval? { file.load()?.lifetime }
}
