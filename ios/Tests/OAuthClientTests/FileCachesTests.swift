import XCTest
@testable import OAuthClient

final class FileCachesTests: XCTestCase {
    private var directory: URL!

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("versola-oauth-tests-\(UUID().uuidString)", isDirectory: true)
            .appendingPathComponent("nested", isDirectory: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: directory.deletingLastPathComponent())
    }

    private let metadata = ProviderMetadata(
        issuer: "https://auth.example.com", authorizationEndpoint: "https://auth.example.com/authorize",
        tokenEndpoint: "https://auth.example.com/token", jwksUri: "https://auth.example.com/jwks",
        codeChallengeMethodsSupported: ["S256"], dpopSigningAlgValuesSupported: ["ES256"]
    )

    private let keys = JsonWebKeySet(keys: [JsonWebKey(kty: "EC", kid: "k1", alg: "ES256", crv: "P-256", x: "x", y: "y")])

    func testMetadataRoundTripsAndTheDirectoryIsCreated() async throws {
        let cache = FileProviderMetadataCache(directory: directory)
        let empty = try await cache.load()
        XCTAssertNil(empty)
        try await cache.save(metadata)
        let loaded = try await cache.load()
        XCTAssertEqual(loaded, metadata)
        let savedAt = try await cache.savedAt()
        XCTAssertNotNil(savedAt)
    }

    func testJwksRoundTrips() async throws {
        let cache = FileJwksCache(directory: directory)
        let empty = try await cache.load()
        XCTAssertNil(empty)
        try await cache.save(keys)
        let loaded = try await cache.load()
        XCTAssertEqual(loaded, keys)
    }

    func testSecondSaveReplacesTheFirst() async throws {
        let cache = FileJwksCache(directory: directory)
        try await cache.save(keys)
        let replacement = JsonWebKeySet(keys: [])
        try await cache.save(replacement)
        let loaded = try await cache.load()
        XCTAssertEqual(loaded, replacement)
    }

    func testCorruptMetadataFileReadsNilAndIsDeleted() async throws {
        let cache = FileProviderMetadataCache(directory: directory)
        try await cache.save(metadata)
        let file = directory.appendingPathComponent("provider-metadata.json")
        try Data("{ this is not json".utf8).write(to: file)

        let loaded = try await cache.load()
        XCTAssertNil(loaded)
        XCTAssertFalse(FileManager.default.fileExists(atPath: file.path), "a corrupt file is removed, not re-read forever")
        // And the cache works again afterwards.
        try await cache.save(metadata)
        let again = try await cache.load()
        XCTAssertEqual(again, metadata)
    }

    func testCorruptJwksFileReadsNil() async throws {
        let cache = FileJwksCache(directory: directory)
        try await cache.save(keys)
        try Data([0xFF, 0x00, 0x13]).write(to: directory.appendingPathComponent("jwks.json"))
        let loaded = try await cache.load()
        XCTAssertNil(loaded)
    }

    func testFilesAreExcludedFromBackup() async throws {
        let cache = FileJwksCache(directory: directory)
        try await cache.save(keys)
        let file = directory.appendingPathComponent("jwks.json")
        let values = try file.resourceValues(forKeys: [.isExcludedFromBackupKey])
        XCTAssertEqual(values.isExcludedFromBackup, true)
        let directoryValues = try directory.resourceValues(forKeys: [.isExcludedFromBackupKey])
        XCTAssertEqual(directoryValues.isExcludedFromBackup, true)
    }
}
