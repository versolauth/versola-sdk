import CryptoKit
import os
import XCTest
@testable import OAuthClient

/// A key store in memory: the key's logic needs no Keychain.
private final class MemoryKeyStore: DpopKeyStore {
    private let slot = OSAllocatedSlot()
    func load() throws -> Data? { slot.get() }
    func save(_ data: Data) throws { slot.set(data) }
    func delete() throws { slot.set(nil) }
}

private final class OSAllocatedSlot: Sendable {
    private let lock = OSAllocatedUnfairLock<Data?>(initialState: nil)
    func get() -> Data? { lock.withLock { $0 } }
    func set(_ value: Data?) { lock.withLock { $0 = value } }
}

final class SecureEnclaveDpopKeyTests: XCTestCase {
    /// The enclave is declared absent: a Mac host may report one it cannot use unsigned, and a
    /// test must not depend on which Mac it runs on. The enclave tier itself is the device tier.
    private func softwareKey(store: MemoryKeyStore = MemoryKeyStore(), logger: (any OAuthLogger)? = nil) -> SecureEnclaveDpopKey {
        SecureEnclaveDpopKey(store: store, requireHardware: false, logger: logger, secureEnclaveAvailable: false)
    }

    private func decode(_ base64url: String) throws -> Data {
        var s = base64url.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while s.count % 4 != 0 { s += "=" }
        return try XCTUnwrap(Data(base64Encoded: s))
    }

    func testSignatureVerifiesWithTheAdvertisedPublicKey() async throws {
        let key = softwareKey()
        let message = Data("header.payload".utf8)
        let signature = try await key.sign(message)
        let jwk = try await key.publicJwk()

        XCTAssertEqual(signature.count, 64, "ES256 is R || S, 64 bytes, not DER")
        let x = try decode(try XCTUnwrap(jwk.x))
        let y = try decode(try XCTUnwrap(jwk.y))
        let publicKey = try P256.Signing.PublicKey(x963Representation: Data([0x04]) + x + y)
        let parsed = try P256.Signing.ECDSASignature(rawRepresentation: signature)
        XCTAssertTrue(publicKey.isValidSignature(parsed, for: message))
        // Negative: the same signature over other bytes does not verify.
        XCTAssertFalse(publicKey.isValidSignature(parsed, for: Data("header.other".utf8)))
    }

    func testJwkIsAnEcP256PublicKeyWith32ByteCoordinatesAndNothingElse() async throws {
        let jwk = try await softwareKey().publicJwk()
        XCTAssertEqual(jwk.kty, "EC")
        XCTAssertEqual(jwk.crv, "P-256")
        XCTAssertEqual(try decode(try XCTUnwrap(jwk.x)).count, 32)
        XCTAssertEqual(try decode(try XCTUnwrap(jwk.y)).count, 32)
        XCTAssertFalse(try XCTUnwrap(jwk.x).contains("="))
        XCTAssertNil(jwk.kid)
        XCTAssertNil(jwk.alg)
        XCTAssertNil(jwk.use)
        XCTAssertNil(jwk.n)
        XCTAssertNil(jwk.e)
    }

    func testAttestationReportsSoftwareWhenTheEnclaveIsUnavailable() async throws {
        let attestation = try await softwareKey().attestation()
        XCTAssertEqual(attestation, KeyAttestation(tier: .software))
        XCTAssertNotEqual(attestation.tier, .secureEnclave)
    }

    func testSoftwareTierWarnsOnceAndNamesNoKeyMaterial() async throws {
        let logger = RecordingLogger()
        let key = softwareKey(logger: logger)
        _ = try await key.publicJwk()
        _ = try await key.sign(Data("x".utf8))
        _ = try await key.attestation()
        XCTAssertEqual(logger.warnings.count, 1)
    }

    func testRequireHardwareThrowsOnAHostWithoutAnEnclave() async {
        let store = MemoryKeyStore()
        let key = SecureEnclaveDpopKey(store: store, requireHardware: true, secureEnclaveAvailable: false)
        for operation in [
            { _ = try await key.publicJwk() }, { _ = try await key.sign(Data()) }, { _ = try await key.attestation() },
        ] {
            do {
                try await operation()
                XCTFail("expected hardwareBindingUnavailable")
            } catch OAuthError.configuration(.hardwareBindingUnavailable) {
            } catch {
                XCTFail("\(error)")
            }
        }
        XCTAssertNil(try store.load(), "no software key may be left behind by a refused fallback")
    }

    func testRequireHardwareAlsoRefusesAPersistedSoftwareKey() async throws {
        let store = MemoryKeyStore()
        _ = try await softwareKey(store: store).publicJwk()
        let strict = SecureEnclaveDpopKey(store: store, requireHardware: true, secureEnclaveAvailable: false)
        do {
            _ = try await strict.attestation()
            XCTFail("expected hardwareBindingUnavailable")
        } catch OAuthError.configuration(.hardwareBindingUnavailable) {
        }
    }

    func testStoredKeyReloadsWithTheSamePublicKey() async throws {
        let store = MemoryKeyStore()
        let first = try await softwareKey(store: store).publicJwk()
        let reloaded = softwareKey(store: store)
        let second = try await reloaded.publicJwk()
        XCTAssertEqual(first, second)
        let attestation = try await reloaded.attestation()
        XCTAssertEqual(attestation.tier, .software, "the tier is read back from the loaded key")
        // A signature from the reloaded key verifies under the first run's public key.
        let message = Data("m".utf8)
        let signature = try await reloaded.sign(message)
        let publicKey = try P256.Signing.PublicKey(
            x963Representation: Data([0x04]) + (try decode(try XCTUnwrap(first.x))) + (try decode(try XCTUnwrap(first.y)))
        )
        XCTAssertTrue(publicKey.isValidSignature(try P256.Signing.ECDSASignature(rawRepresentation: signature), for: message))
    }

    func testDestroyDeletesTheKeyAndTheNextOneIsDifferent() async throws {
        let store = MemoryKeyStore()
        let key = softwareKey(store: store)
        let before = try await key.publicJwk()
        try await key.destroy()
        XCTAssertNil(try store.load())
        let after = try await key.publicJwk()
        XCTAssertNotEqual(before, after)
    }

    func testRacingFirstUsesShareOneKey() async throws {
        let key = softwareKey()
        let jwks = try await withThrowingTaskGroup(of: JsonWebKey.self) { group in
            for _ in 0..<20 { group.addTask { try await key.publicJwk() } }
            var all: [JsonWebKey] = []
            for try await jwk in group { all.append(jwk) }
            return all
        }
        XCTAssertEqual(Set(jwks.map { $0.x }).count, 1)
    }

    func testAnUnreadableStoredBlobFailsClosedAndIsNotReplacedBehindTheGrant() async throws {
        let store = MemoryKeyStore()
        try store.save(Data([0x09, 0x01, 0x02]))
        let key = softwareKey(store: store)
        do {
            _ = try await key.publicJwk()
            XCTFail("expected hardwareBindingUnavailable")
        } catch OAuthError.configuration(.hardwareBindingUnavailable) {
        }
        XCTAssertEqual(try store.load(), Data([0x09, 0x01, 0x02]))
        // destroy() is the way out.
        try await key.destroy()
        _ = try await key.publicJwk()
    }

    func testAnEnclaveBlobOnAHostWithoutAnEnclaveFailsClosed() async throws {
        let store = MemoryKeyStore()
        try store.save(Data([0x01, 0xAA, 0xBB]))
        let key = softwareKey(store: store)
        do {
            _ = try await key.attestation()
            XCTFail("expected hardwareBindingUnavailable")
        } catch OAuthError.configuration(.hardwareBindingUnavailable) {
        }
    }
}
