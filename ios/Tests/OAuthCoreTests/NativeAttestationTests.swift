import Foundation
import XCTest
@testable import OAuthCore

/// The bytes and names of the attestation contract, held to values computed outside this code.
final class NativeAttestationTests: XCTestCase {
    private func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }

    func testClientDataHashIsTheVectorTheSpecAndEdgePublish() {
        // `SHA-256("versola-attest-v1\nmobile-app\nJKT\nJTI")`, from `spec/server-dependencies.md`: computed
        // with `hashlib` and checked by edge's own spec, so neither side's hashing is the other's reading of it.
        let hash = NativeAttestation.clientDataHash(clientId: "mobile-app", jkt: "JKT", jti: "JTI")

        XCTAssertEqual(hex(hash), "59241b9875b6c77d3d24ca23f08be296ecd13f10e52a5ffa3e7be2e6f07b6860")
    }

    func testClientDataHashIsBoundToTheClientTheKeyAndTheProof() {
        let base = NativeAttestation.clientDataHash(clientId: "a", jkt: "k", jti: "j")

        XCTAssertNotEqual(base, NativeAttestation.clientDataHash(clientId: "b", jkt: "k", jti: "j"))
        XCTAssertNotEqual(base, NativeAttestation.clientDataHash(clientId: "a", jkt: "l", jti: "j"))
        XCTAssertNotEqual(base, NativeAttestation.clientDataHash(clientId: "a", jkt: "k", jti: "i"))
        // Fields are told apart by the separator, so moving a character across it is another hash.
        XCTAssertNotEqual(
            NativeAttestation.clientDataHash(clientId: "a", jkt: "bk", jti: "j"),
            NativeAttestation.clientDataHash(clientId: "ab", jkt: "k", jti: "j")
        )
    }

    func testAnAttestationIsThePlatformTheKeyIdAndTheObjectInBase64() {
        let fields = NativeAttestation.fields(keyId: "key-1", attestationObject: Data([0xfb, 0xff, 0x3e]))

        XCTAssertEqual(fields, [
            NativeStartField(name: "attestation_platform", value: "ios"),
            NativeStartField(name: "attestation_key_id", value: "key-1"),
            NativeStartField(name: "attestation_object", value: "+/8+"),
        ])
    }

    func testAnAssertionIsThePlatformTheKeyIdAndTheAssertionInBase64() {
        let fields = NativeAttestation.fields(keyId: "key-1", assertion: Data([1, 2]))

        XCTAssertEqual(fields.map(\.name), ["attestation_platform", "attestation_key_id", "attestation_assertion"])
        XCTAssertEqual(fields.last?.value, "AQI=")
        // Either an object or an assertion, never both: edge refuses a request that carries the two.
        XCTAssertFalse(fields.contains { $0.name == "attestation_object" })
    }

    // MARK: the jti of a proof

    private func proof(payload: String) -> String {
        "\(Base64Url.encode(Data("{\"alg\":\"ES256\"}".utf8))).\(Base64Url.encode(Data(payload.utf8))).c2ln"
    }

    func testJtiOfAProofIsReadFromItsPayload() {
        XCTAssertEqual(NativeAttestation.jti(ofProof: proof(payload: #"{"htm":"POST","jti":"abc-123"}"#)), "abc-123")
    }

    func testJtiOfAnythingThatIsNotAProofWithOneIsNil() {
        XCTAssertNil(NativeAttestation.jti(ofProof: "not-a-jws"))
        XCTAssertNil(NativeAttestation.jti(ofProof: "a.b"))
        XCTAssertNil(NativeAttestation.jti(ofProof: "a.b.c.d"))
        XCTAssertNil(NativeAttestation.jti(ofProof: "e30.***.c2ln"))
        XCTAssertNil(NativeAttestation.jti(ofProof: proof(payload: #"{"htm":"POST"}"#)))
        XCTAssertNil(NativeAttestation.jti(ofProof: proof(payload: #"{"jti":""}"#)))
        XCTAssertNil(NativeAttestation.jti(ofProof: proof(payload: #"{"jti":7}"#)))
        XCTAssertNil(NativeAttestation.jti(ofProof: proof(payload: "[1,2]")))
    }
}
