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

/// The discovered metadata on disk. The client points it at
/// `Application Support/versola-oauth/<storageKey>/`. It survives logout on purpose: a re-login
/// should not need a round trip to the discovery document.
public actor FileProviderMetadataCache: ProviderMetadataCache {
    private let file: JSONFile<ProviderMetadata>

    public init(directory: URL) {
        file = JSONFile(directory: directory, name: "provider-metadata.json")
    }

    public func load() async throws -> ProviderMetadata? { file.load() }
    public func save(_ metadata: ProviderMetadata) async throws { try file.save(metadata) }

    /// When the document was last written: the cache has no age in its contract, and the
    /// client refetches a 24-hour-old one (`spec/oauth-sdk-api.md` section 4).
    public func savedAt() -> Date? { file.modificationDate() }
}

/// The provider's key set on disk, unencrypted (public keys).
public actor FileJwksCache: JwksCache {
    private let file: JSONFile<JsonWebKeySet>

    public init(directory: URL) {
        file = JSONFile(directory: directory, name: "jwks.json")
    }

    public func load() async throws -> JsonWebKeySet? { file.load() }
    public func save(_ set: JsonWebKeySet) async throws { try file.save(set) }
}
