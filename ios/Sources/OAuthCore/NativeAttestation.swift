import CryptoKit
import Foundation

/// One form field of the evidence an app sends on `POST /native/start`.
package struct NativeStartField: Sendable, Equatable {
    package let name: String
    package let value: String

    package init(name: String, value: String) {
        self.name = name
        self.value = value
    }
}

/// What an app proves about itself on `/native/start`, as the extra form fields the request carries
/// (`spec/server-dependencies.md`, "App attestation on `/native/start`"). Evidence, not a
/// permission: an implementation returns what the device has, and an empty list is a device with
/// nothing to give. Edge's policy for the client decides whether that is acceptable, and the SDK
/// neither retries with other evidence nor lowers a check when edge refuses.
///
/// It takes the `jkt` and the `jti` of the proof that goes on the same request, because an iOS
/// assertion is made for exactly that proof: the facade mints the proof first and asks for the
/// evidence second. Nothing in the SDK calls this yet -- there is no iOS counterpart of the Versola
/// facade -- and the seam is here so that the facade that does can take it as it is.
package protocol NativeStartAttestation: Sendable {
    /// `nonce` is the server nonce of the proof that goes on the same request, when it carries one (edge asks for it with
    /// `use_dpop_nonce`): it is part of what an App Attest assertion is made over, so that one cannot be made ahead of time
    /// for a `jti` the app chose.
    func fields(clientId: String, jkt: String, jti: String, nonce: String?) async throws -> [NativeStartField]

    /// Edge did not take the evidence last handed out, and what it said means the next request must
    /// not build on it: an App Attest key that edge never saw attested (the request that carried the
    /// attestation object did not reach it). The implementation forgets what it keeps about that key.
    func evidenceNotAccepted() async
}

extension NativeStartAttestation {
    package func evidenceNotAccepted() async {}

    /// For a caller whose proof carries no nonce.
    package func fields(clientId: String, jkt: String, jti: String) async throws -> [NativeStartField] {
        try await fields(clientId: clientId, jkt: jkt, jti: jti, nonce: nil)
    }
}

/// The parts of the attestation contract that are bytes and names, fixed by the spec and shared with
/// edge and with Android.
package enum NativeAttestation {
    /// Domain separator of everything hashed for edge: a hash made for this purpose is good for no other.
    static let domain = "versola-attest-v1"

    /// What an iOS app hands App Attest as its client data hash, so that an attestation or an assertion
    /// is for one request of one client by one DPoP key:
    /// `SHA-256("versola-attest-v1\n" + clientId + "\n" + jkt + "\n" + jti)`, and when the proof carries a
    /// server `nonce`, `... + "\n" + jti + "\n" + nonce`.
    ///
    /// `jkt` is the thumbprint of the DPoP key and `jti` the `jti` of the proof sent on the same
    /// request, which edge's replay guard has made single-use. The nonce is the one value in it the
    /// server chose. Not a secret and not a MAC: App Attest signs it, which is what ties it to the key.
    package static func clientDataHash(clientId: String, jkt: String, jti: String, nonce: String? = nil) -> Data {
        let tail = nonce.flatMap { $0.isEmpty ? nil : "\n\($0)" } ?? ""
        return Data(SHA256.hash(data: Data("\(domain)\n\(clientId)\n\(jkt)\n\(jti)\(tail)".utf8)))
    }

    /// Why this device cannot attest, said instead of evidence: `unsupported` (the device does not support App Attest),
    /// `service_unavailable` (Apple's service could not be reached). Edge counts it as an outcome of its own, and under
    /// `enforce` refuses the request all the same.
    package static func unavailable(_ reason: String) -> [NativeStartField] {
        [NativeStartField(name: "attestation_unavailable", value: reason)]
    }

    /// The first request of an App Attest key: the key id and its attestation object, base64.
    package static func fields(keyId: String, attestationObject: Data) -> [NativeStartField] {
        base(keyId: keyId) + [NativeStartField(name: "attestation_object", value: attestationObject.base64EncodedString())]
    }

    /// Every later request of the key: the key id and an assertion, base64.
    package static func fields(keyId: String, assertion: Data) -> [NativeStartField] {
        base(keyId: keyId) + [NativeStartField(name: "attestation_assertion", value: assertion.base64EncodedString())]
    }

    private static func base(keyId: String) -> [NativeStartField] {
        [
            NativeStartField(name: "attestation_platform", value: "ios"),
            NativeStartField(name: "attestation_key_id", value: keyId),
        ]
    }

    /// The `nonce` a DPoP proof carries, read as [`jti(ofProof:)`] reads the `jti`: nil for a proof without one.
    package static func nonce(ofProof proof: String) -> String? {
        let parts = proof.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3,
              let payload = Base64Url.decode(String(parts[1])),
              let object = try? JSONSerialization.jsonObject(with: payload) as? [String: Any],
              let nonce = object["nonce"] as? String, !nonce.isEmpty
        else { return nil }
        return nonce
    }

    /// The `jti` a DPoP proof carries, read from its payload without checking the signature: the proof
    /// is the SDK's own, minted a moment ago, and only its identifier is wanted. Nil for anything that
    /// is not a three-part JWS with a string `jti`.
    package static func jti(ofProof proof: String) -> String? {
        let parts = proof.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3,
              let payload = Base64Url.decode(String(parts[1])),
              let object = try? JSONSerialization.jsonObject(with: payload) as? [String: Any],
              let jti = object["jti"] as? String, !jti.isEmpty
        else { return nil }
        return jti
    }
}
