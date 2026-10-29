import CryptoKit
import Foundation
import Security
import XCTest
@testable import OAuthCore

// Keys, JWKS documents, signed tokens and an HTTP stub for the JOSE tests. Written against
// Security.framework and CryptoKit directly and not against the code under test, so a bug in the
// verifier's DER encoding or key construction cannot be mirrored here and cancel out: this file
// is the second opinion (and `JwsTests` adds an OpenSSL vector for the PSS parameters).

/// Throwaway RSA key pair. Only the DER of the private key is kept, so the value is `Sendable`
/// without wrapping a `SecKey`.
struct JoseTestRSAKey: Sendable {
    let privateDER: Data
    let n: Data
    let e: Data

    static func generate(bits: Int = 2048) -> JoseTestRSAKey {
        let attributes: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits as String: bits]
        let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, nil)!
        let publicKey = SecKeyCopyPublicKey(privateKey)!
        let privateDER = SecKeyCopyExternalRepresentation(privateKey, nil)! as Data
        let publicDER = SecKeyCopyExternalRepresentation(publicKey, nil)! as Data
        var reader = JoseDERReader(publicDER)
        reader.enterSequence()
        let n = reader.integer()
        let e = reader.integer()
        return JoseTestRSAKey(privateDER: privateDER, n: n, e: e)
    }

    func jwk(kid: String?, alg: String? = nil, use: String? = nil) -> JsonWebKey {
        JsonWebKey(kty: "RSA", kid: kid, alg: alg, use: use, n: JoseBase64Url.encode(n), e: JoseBase64Url.encode(e))
    }

    func sign(_ alg: String, _ input: Data) -> Data {
        let attributes: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeRSA, kSecAttrKeyClass as String: kSecAttrKeyClassPrivate]
        let key = SecKeyCreateWithData(privateDER as CFData, attributes as CFDictionary, nil)!
        let algorithm: SecKeyAlgorithm
        switch alg {
        case "RS256": algorithm = .rsaSignatureMessagePKCS1v15SHA256
        case "RS384": algorithm = .rsaSignatureMessagePKCS1v15SHA384
        case "RS512": algorithm = .rsaSignatureMessagePKCS1v15SHA512
        case "PS256": algorithm = .rsaSignatureMessagePSSSHA256
        case "PS384": algorithm = .rsaSignatureMessagePSSSHA384
        case "PS512": algorithm = .rsaSignatureMessagePSSSHA512
        default: fatalError("not an RSA algorithm: \(alg)")
        }
        return SecKeyCreateSignature(key, algorithm, input as CFData, nil)! as Data
    }
}

/// A DER reader for the one shape the tests take apart: `SEQUENCE { INTEGER, INTEGER }`.
struct JoseDERReader {
    private let bytes: [UInt8]
    private var index = 0

    init(_ data: Data) { bytes = Array(data) }

    private mutating func length() -> Int {
        let first = Int(bytes[index])
        index += 1
        if first < 0x80 { return first }
        var value = 0
        for _ in 0..<(first & 0x7F) {
            value = value << 8 | Int(bytes[index])
            index += 1
        }
        return value
    }

    mutating func enterSequence() {
        precondition(bytes[index] == 0x30)
        index += 1
        _ = length()
    }

    /// The unsigned magnitude of the next INTEGER, leading zero byte dropped.
    mutating func integer() -> Data {
        precondition(bytes[index] == 0x02)
        index += 1
        let count = length()
        var value = Array(bytes[index..<index + count])
        index += count
        while value.count > 1 && value[0] == 0 { value.removeFirst() }
        return Data(value)
    }
}

/// Throwaway EC key of one of the three JOSE curves.
struct JoseTestECKey: Sendable {
    let alg: String
    let crv: String
    private let raw: Data
    let x: Data
    let y: Data

    private init(alg: String, crv: String, raw: Data, point: Data, width: Int) {
        self.alg = alg
        self.crv = crv
        self.raw = raw
        self.x = point.subdata(in: 1..<(1 + width))
        self.y = point.subdata(in: (1 + width)..<(1 + 2 * width))
    }

    static func generate(_ alg: String) -> JoseTestECKey {
        switch alg {
        case "ES256":
            let key = P256.Signing.PrivateKey()
            return JoseTestECKey(alg: alg, crv: "P-256", raw: key.rawRepresentation, point: key.publicKey.x963Representation, width: 32)
        case "ES384":
            let key = P384.Signing.PrivateKey()
            return JoseTestECKey(alg: alg, crv: "P-384", raw: key.rawRepresentation, point: key.publicKey.x963Representation, width: 48)
        default:
            let key = P521.Signing.PrivateKey()
            return JoseTestECKey(alg: "ES512", crv: "P-521", raw: key.rawRepresentation, point: key.publicKey.x963Representation, width: 66)
        }
    }

    func jwk(kid: String?, alg: String? = nil, use: String? = nil) -> JsonWebKey {
        JsonWebKey(kty: "EC", kid: kid, alg: alg, use: use, crv: crv, x: JoseBase64Url.encode(x), y: JoseBase64Url.encode(y))
    }

    func sign(_ input: Data) -> Data {
        switch alg {
        case "ES256": return try! P256.Signing.PrivateKey(rawRepresentation: raw).signature(for: input).rawRepresentation
        case "ES384": return try! P384.Signing.PrivateKey(rawRepresentation: raw).signature(for: input).rawRepresentation
        default: return try! P521.Signing.PrivateKey(rawRepresentation: raw).signature(for: input).rawRepresentation
        }
    }
}

/// Keys are generated once per test run: RSA 2048 is the slow part.
enum JoseTestKeys {
    static let rsa = JoseTestRSAKey.generate()
    static let rsaOther = JoseTestRSAKey.generate()
    static let p256 = JoseTestECKey.generate("ES256")
    static let p256Other = JoseTestECKey.generate("ES256")
    static let p384 = JoseTestECKey.generate("ES384")
    static let p521 = JoseTestECKey.generate("ES512")
}

enum JoseTestTokens {
    /// `header.payload.signature`. `sign` gets the signing input; nil leaves the signature empty
    /// (an `alg: none` token).
    static func jws(header: String, payload: String, sign: ((Data) -> Data)?) -> String {
        let input = JoseBase64Url.encode(Data(header.utf8)) + "." + JoseBase64Url.encode(Data(payload.utf8))
        let signature = sign.map { $0(Data(input.utf8)) } ?? Data()
        return input + "." + JoseBase64Url.encode(signature)
    }

    static func header(alg: String, kid: String?) -> String {
        var parts = ["\"alg\":\"\(alg)\"", "\"typ\":\"JWT\""]
        if let kid { parts.append("\"kid\":\"\(kid)\"") }
        return "{" + parts.joined(separator: ",") + "}"
    }

    static func rsa(_ alg: String, _ key: JoseTestRSAKey = JoseTestKeys.rsa, payload: String, kid: String? = "rsa") -> String {
        jws(header: header(alg: alg, kid: kid), payload: payload, sign: { key.sign(alg, $0) })
    }

    static func ec(_ key: JoseTestECKey, payload: String, kid: String?) -> String {
        jws(header: header(alg: key.alg, kid: kid), payload: payload, sign: { key.sign($0) })
    }

    /// A claims object as compact JSON text; a nil value is left out.
    static func json(_ members: [String: Any?]) -> String {
        let object = members.compactMapValues { $0 }
        let data = try! JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
        return String(decoding: data, as: UTF8.self)
    }

    /// Header and claims of a compact JWS, decoded without checking anything.
    static func decode(_ compact: String) -> (header: [String: Any], claims: [String: Any], parts: [String]) {
        let parts = compact.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        func object(_ segment: String) -> [String: Any] {
            try! JSONSerialization.jsonObject(with: JoseBase64Url.decode(segment)!) as! [String: Any]
        }
        return (object(parts[0]), object(parts[1]), parts)
    }

    static func jwks(_ keys: JsonWebKey...) -> Data {
        try! JSONEncoder().encode(JsonWebKeySet(keys: keys))
    }
}

/// An `HTTPClient` stub keyed by URL path: answers are queued per path, every request is
/// recorded, and a request nobody queued an answer for is a 404 that the test then sees in the
/// count. Optionally holds every request until `release()`, to put callers in flight together.
actor JoseStubHTTP: HTTPClient {
    private var queues: [String: [Result<HTTPResponse, Error>]] = [:]
    private(set) var requests: [HTTPRequest] = []
    private var holding: Bool
    private var waiting: [CheckedContinuation<Void, Never>] = []

    init(hold: Bool = false) { holding = hold }

    func enqueue(_ path: String, status: Int = 200, headers: [String: String] = [:], body: Data = Data()) {
        queues[path, default: []].append(.success(HTTPResponse(statusCode: status, headers: headers, body: body)))
    }

    func enqueue(_ path: String, status: Int = 200, headers: [String: String] = [:], text: String) {
        enqueue(path, status: status, headers: headers, body: Data(text.utf8))
    }

    func enqueueFailure(_ path: String) {
        queues[path, default: []].append(.failure(URLError(.notConnectedToInternet)))
    }

    func release() {
        holding = false
        for continuation in waiting { continuation.resume() }
        waiting = []
    }

    func requestCount(path: String? = nil) -> Int {
        guard let path else { return requests.count }
        return requests.filter { $0.url.path == path }.count
    }

    func send(_ request: HTTPRequest) async throws -> HTTPResponse {
        requests.append(request)
        if holding { await withCheckedContinuation { waiting.append($0) } }
        guard var queue = queues[request.url.path], !queue.isEmpty else { return HTTPResponse(statusCode: 404) }
        let next = queue.removeFirst()
        queues[request.url.path] = queue
        return try next.get()
    }
}

/// Runs `block` and hands back what it threw, or fails the test when it did not.
func joseThrown(file: StaticString = #filePath, line: UInt = #line, _ block: () async throws -> Void) async -> Error? {
    do {
        try await block()
        XCTFail("expected an error", file: file, line: line)
        return nil
    } catch {
        return error
    }
}
