import Foundation
import Security
@testable import OAuthCore

/// The key the ID-token scenarios (25 to 27) re-sign with: the proxy serves its JWKS in place
/// of the provider's and rewrites the token response's `id_token` so that exactly the claim
/// under test differs. Generated per test; nothing here is a real key.
struct HarnessSigner: Sendable {
    let kid: String
    /// The private key as PKCS#1 bytes (`SecKey` is not Sendable); rebuilt per use.
    private let keyData: Data

    init(kid: String = "harness") {
        self.kid = kid
        let key = SecKeyCreateRandomKey([kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits: 2048] as CFDictionary, nil)!
        keyData = SecKeyCopyExternalRepresentation(key, nil)! as Data
    }

    private var key: SecKey {
        SecKeyCreateWithData(keyData as CFData, [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeyClass: kSecAttrKeyClassPrivate] as CFDictionary, nil)!
    }

    func jwks() -> String {
        let data = SecKeyCopyExternalRepresentation(SecKeyCopyPublicKey(key)!, nil)! as Data
        // PKCS#1 RSAPublicKey: SEQUENCE { INTEGER n, INTEGER e }.
        var reader = DERReader(data)
        reader.expectSequence()
        let n = reader.integer(), e = reader.integer()
        return #"{"keys":[{"kty":"RSA","kid":"\#(kid)","alg":"RS256","use":"sig","n":"\#(Base64Url.encode(n))","e":"\#(Base64Url.encode(e))"}]}"#
    }

    /// `idToken`'s payload with `mutate` applied, signed by this key under `alg` and `kid`.
    func resign(_ idToken: String, alg: String = "RS256", kid: String? = nil, mutate: ([String: Any]) -> [String: Any]) -> String {
        let payload = (try? JSONSerialization.jsonObject(with: Base64Url.decode(String(idToken.split(separator: ".")[1]))!)) as? [String: Any] ?? [:]
        let mutated = mutate(payload)
        var header: [String: Any] = ["alg": alg, "typ": "JWT"]
        if let kid = kid ?? (alg == "none" || alg == "HS256" ? nil : self.kid) { header["kid"] = kid }
        let signingInput = "\(Base64Url.encode(try! JSONSerialization.data(withJSONObject: header, options: [.sortedKeys]))).\(Base64Url.encode(try! JSONSerialization.data(withJSONObject: mutated, options: [.sortedKeys])))"
        let signature: Data
        switch alg {
        case "RS256": signature = SecKeyCreateSignature(key, .rsaSignatureMessagePKCS1v15SHA256, Data(signingInput.utf8) as CFData, nil)! as Data
        case "none": signature = Data()
        case "HS256":
            // The classic algorithm-confusion attempt: the client id as the HMAC key.
            signature = Data(CryptoHelpers.hmacSHA256(key: Data(Provider.clientId.utf8), message: Data(signingInput.utf8)))
        default: fatalError("no signer for \(alg)")
        }
        return "\(signingInput).\(Base64Url.encode(signature))"
    }

    static func withIdToken(_ response: [String: Any], _ idToken: String) -> [String: Any] {
        var copy = response
        copy["id_token"] = idToken
        return copy
    }

    private struct DERReader {
        var data: Data
        var index: Int
        init(_ data: Data) { self.data = data; index = data.startIndex }
        mutating func expectSequence() { _ = data[index]; index += 1; _ = length() }
        mutating func integer() -> Data {
            precondition(data[index] == 0x02); index += 1
            let count = length()
            var value = data[index..<(index + count)]; index += count
            while value.first == 0, value.count > 1 { value = value.dropFirst() }
            return Data(value)
        }
        private mutating func length() -> Int {
            let first = Int(data[index]); index += 1
            if first < 0x80 { return first }
            var count = 0
            for _ in 0..<(first & 0x7f) { count = count << 8 | Int(data[index]); index += 1 }
            return count
        }
    }
}

enum CryptoHelpers {
    static func hmacSHA256(key: Data, message: Data) -> [UInt8] {
        import_CryptoKit_HMAC(key: key, message: message)
    }
}
