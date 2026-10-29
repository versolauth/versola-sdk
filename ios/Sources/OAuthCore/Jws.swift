import CryptoKit
import Foundation
import Security

// JWS (RFC 7515) as far as an ID token and a signed UserInfo response need it: parse the compact
// form, pick the provider's key, verify. What the claims mean is the caller's business. Ported
// from Android's `Jws.kt`; the reasons are the same, the platform halves are not (Security.framework
// for RSA, CryptoKit for EC, and no DER conversion because CryptoKit takes JOSE's `R || S`).

/// Why a JWS was refused, before the caller decides what that means for it. An ID token maps it
/// to `idTokenRejected(reason)` and a signed UserInfo response to `userInfoRejected`; the check
/// itself is the same, so it is written once and the reason is the closed enum the ID-token
/// error already has.
///
/// Not an `OAuthError`: it never leaves the validation code. A network failure or a missing
/// capability while verifying is an `OAuthError` and passes through untouched.
public struct JwsRejection: Error, Sendable, Equatable {
    public let reason: IdTokenRejection
    /// What was wrong, for a log line. Never carries a token, a claim value or a key.
    public let detail: String

    public init(_ reason: IdTokenRejection, _ detail: String) {
        self.reason = reason
        self.detail = detail
    }
}

/// The asymmetric JWS algorithms an ID token may use, and nothing else (`spec/oauth-sdk-api.md`
/// section 11). `none` and the HMAC family are not members and cannot become one by
/// configuration: a public client holds no secret to verify an HMAC with, so a token claiming
/// `HS256` is either an attack (the key-confusion downgrade, where the provider's public key is
/// used as the HMAC secret) or a provider this SDK cannot talk to.
public enum JwsAlgorithm: String, Sendable, CaseIterable {
    case RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512

    /// The JWK `kty` a key must have to verify with this algorithm.
    var keyType: String {
        switch self {
        case .RS256, .RS384, .RS512, .PS256, .PS384, .PS512: return "RSA"
        case .ES256, .ES384, .ES512: return "EC"
        }
    }

    var isPSS: Bool {
        switch self {
        case .PS256, .PS384, .PS512: return true
        default: return false
        }
    }

    /// The JWK `crv` of an EC algorithm, nil for RSA. `ES512` is P-521, not P-512 (RFC 7518 3.4).
    var curve: String? {
        switch self {
        case .ES256: return "P-256"
        case .ES384: return "P-384"
        case .ES512: return "P-521"
        default: return nil
        }
    }

    /// Width in bytes of one coordinate, and of each of `R` and `S`; 0 for RSA. A P-521
    /// coordinate is 66 bytes because the curve's order is 521 bits.
    var ecComponentBytes: Int {
        switch self {
        case .ES256: return 32
        case .ES384: return 48
        case .ES512: return 66
        default: return 0
        }
    }

    /// Bytes of the digest; `at_hash` takes the left half of it (Core 3.1.3.6).
    var digestBytes: Int {
        switch self {
        case .RS256, .PS256, .ES256: return 32
        case .RS384, .PS384, .ES384: return 48
        case .RS512, .PS512, .ES512: return 64
        }
    }
}

/// A compact JWS taken apart but not yet trusted: nothing in it means anything until a verifier
/// has said the signature holds.
public struct ParsedJws: Sendable, CustomStringConvertible {
    /// The header's `alg`, `kid` and `typ` when they are strings.
    public let alg: String?
    public let kid: String?
    public let typ: String?
    /// The raw JSON of the payload, the claims set of an ID token or a UserInfo response.
    public let payload: Data
    /// `BASE64URL(header) "." BASE64URL(payload)` as it came: the exact bytes that were signed
    /// (RFC 7515 5.2).
    public let signingInput: Data
    public let signature: Data

    /// The payload as parsed, a JSON object by construction.
    let claims: [String: JoseJSON]

    init(alg: String?, kid: String?, typ: String?, payload: Data, signingInput: Data, signature: Data, claims: [String: JoseJSON]) {
        self.alg = alg
        self.kid = kid
        self.typ = typ
        self.payload = payload
        self.signingInput = signingInput
        self.signature = signature
        self.claims = claims
    }

    /// Claim values and the token itself are secrets-adjacent; print nothing of them.
    public var description: String { "ParsedJws(redacted)" }
}

enum Jws {
    /// RFC 7515 7.2 for the compact form: exactly three dot-separated base64url parts, a header
    /// that is a JSON object with a string `alg`, a payload that is a JSON object (the only
    /// payload an ID token or a UserInfo JWT has).
    ///
    /// A header carrying `crit` is refused: it lists extensions the recipient MUST understand and
    /// this verifier understands none, so accepting it would be ignoring a MUST.
    ///
    /// - Throws: `JwsRejection` with `.malformed`.
    static func parse(_ compact: String) throws -> ParsedJws {
        let parts = compact.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3 else { throw JwsRejection(.malformed, "not three JWS segments") }
        let header = try object(String(parts[0]), "header")
        let payloadBytes = try bytes(String(parts[1]), "payload")
        let claims = try object(from: payloadBytes, "payload")
        guard let signature = JoseBase64Url.decode(String(parts[2])) else {
            throw JwsRejection(.malformed, "signature is not base64url")
        }
        guard case .string(let alg)? = header["alg"] else { throw JwsRejection(.malformed, "header has no string alg") }
        if header["crit"] != nil { throw JwsRejection(.malformed, "unsupported crit header") }
        func text(_ name: String) -> String? {
            if case .string(let value)? = header[name] { return value }
            return nil
        }
        return ParsedJws(
            alg: alg,
            kid: text("kid"),
            typ: text("typ"),
            payload: payloadBytes,
            signingInput: Data("\(parts[0]).\(parts[1])".utf8),
            signature: signature,
            claims: claims
        )
    }

    private static func bytes(_ segment: String, _ what: String) throws -> Data {
        guard let data = JoseBase64Url.decode(segment) else { throw JwsRejection(.malformed, "\(what) is not base64url") }
        return data
    }

    private static func object(_ segment: String, _ what: String) throws -> [String: JoseJSON] {
        try object(from: bytes(segment, what), what)
    }

    private static func object(from data: Data, _ what: String) throws -> [String: JoseJSON] {
        guard let value = JoseJSON.parse(data) else { throw JwsRejection(.malformed, "\(what) is not JSON") }
        guard case .object(let members) = value else { throw JwsRejection(.malformed, "\(what) is not a JSON object") }
        return members
    }
}

/// The signature check alone: one algorithm, one key, one message. Never throws and never
/// crashes on a bad signature or an unusable key; a failure of any kind is `false`, so the caller
/// cannot confuse "did not verify" with "could not be asked".
public enum JwsSignatures {
    /// An RSA key under this size is not one a provider published on purpose.
    static let minimumRSABits = 2048

    /// Whether `signature` over `signingInput` verifies under `key` for `algorithm`.
    ///
    /// A key of the wrong type or size is refused rather than handed to the platform to fail (or,
    /// worse, not fail): ES256 with a P-384 key is not ES256.
    public static func verifies(algorithm: JwsAlgorithm, key: JsonWebKey, signingInput: Data, signature: Data) -> Bool {
        guard suits(key, algorithm) else { return false }
        return algorithm.keyType == "RSA"
            ? verifyRSA(algorithm, key, signingInput, signature)
            : verifyEC(algorithm, key, signingInput, signature)
    }

    /// Whether `key` is one `algorithm` may be verified with: the right type, an RSA modulus of
    /// at least 2048 bits, an EC curve and coordinate width that match the algorithm.
    static func suits(_ key: JsonWebKey, _ algorithm: JwsAlgorithm) -> Bool {
        guard key.kty == algorithm.keyType else { return false }
        if algorithm.keyType == "RSA" {
            guard let n = key.n.flatMap(JoseBase64Url.decode), let e = key.e.flatMap(JoseBase64Url.decode) else { return false }
            let modulus = DER.stripLeadingZeros(n)
            let exponent = DER.stripLeadingZeros(e)
            guard modulus.count * 8 - (modulus.first?.leadingZeroBitCount ?? 8) >= minimumRSABits else { return false }
            // An even exponent is not an RSA public exponent; 1 is not one either.
            guard let last = exponent.last, last & 1 == 1, exponent != [1] else { return false }
            return true
        }
        guard key.crv == algorithm.curve,
              let x = key.x.flatMap(JoseBase64Url.decode), x.count == algorithm.ecComponentBytes,
              let y = key.y.flatMap(JoseBase64Url.decode), y.count == algorithm.ecComponentBytes
        else { return false }
        return true
    }

    private static func verifyRSA(_ algorithm: JwsAlgorithm, _ key: JsonWebKey, _ message: Data, _ signature: Data) -> Bool {
        guard let n = key.n.flatMap(JoseBase64Url.decode), let e = key.e.flatMap(JoseBase64Url.decode) else { return false }
        // SecKeyCreateWithData wants PKCS#1: RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }.
        let der = DER.sequence(DER.integer(n) + DER.integer(e))
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
        ]
        guard let secKey = SecKeyCreateWithData(der as CFData, attributes as CFDictionary, nil) else { return false }
        let secAlgorithm: SecKeyAlgorithm
        switch algorithm {
        case .RS256: secAlgorithm = .rsaSignatureMessagePKCS1v15SHA256
        case .RS384: secAlgorithm = .rsaSignatureMessagePKCS1v15SHA384
        case .RS512: secAlgorithm = .rsaSignatureMessagePKCS1v15SHA512
        // RFC 7518 3.5: MGF1 with the same digest and a salt as long as the digest, which is what
        // Security.framework's PSS algorithms do (proven against an OpenSSL vector in JwsTests).
        case .PS256: secAlgorithm = .rsaSignatureMessagePSSSHA256
        case .PS384: secAlgorithm = .rsaSignatureMessagePSSSHA384
        case .PS512: secAlgorithm = .rsaSignatureMessagePSSSHA512
        default: return false
        }
        guard SecKeyIsAlgorithmSupported(secKey, .verify, secAlgorithm) else { return false }
        return SecKeyVerifySignature(secKey, secAlgorithm, message as CFData, signature as CFData, nil)
    }

    private static func verifyEC(_ algorithm: JwsAlgorithm, _ key: JsonWebKey, _ message: Data, _ signature: Data) -> Bool {
        guard let x = key.x.flatMap(JoseBase64Url.decode), let y = key.y.flatMap(JoseBase64Url.decode) else { return false }
        // The uncompressed point; CryptoKit refuses one that is not on the curve.
        let point = Data([0x04]) + x + y
        do {
            // JOSE's signature is already R || S (RFC 7515 A.3.1), which is CryptoKit's raw form.
            switch algorithm {
            case .ES256:
                let publicKey = try P256.Signing.PublicKey(x963Representation: point)
                return publicKey.isValidSignature(try P256.Signing.ECDSASignature(rawRepresentation: signature), for: message)
            case .ES384:
                let publicKey = try P384.Signing.PublicKey(x963Representation: point)
                return publicKey.isValidSignature(try P384.Signing.ECDSASignature(rawRepresentation: signature), for: message)
            case .ES512:
                let publicKey = try P521.Signing.PublicKey(x963Representation: point)
                return publicKey.isValidSignature(try P521.Signing.ECDSASignature(rawRepresentation: signature), for: message)
            default:
                return false
            }
        } catch {
            return false
        }
    }
}

/// Parses a compact JWS and proves it was signed by a key the provider publishes, which is the
/// part ID-token validation and signed-UserInfo verification share. Everything after the
/// signature (`iss`, `aud`, times) is the caller's, because it differs.
///
/// Order is part of the contract, and cheap checks come first so that a refused token costs
/// nothing: structure, then the algorithm (closed set, then the provider's advertised list), and
/// only then `jwks_uri` and the network. In particular `none` and `HS256` are refused before
/// anything is fetched, so a forged token cannot be used to make the SDK send requests.
///
/// A key is chosen by `kid`; a token without one is checked against the only suitable key, and
/// refused when several are (guessing which to try is how a verifier ends up accepting a
/// signature from a key the provider retired). When no key verifies, the key set is fetched once
/// more, because that is what a rotation looks like, and then the token is refused; a set that
/// was fetched by this very call is never fetched again.
public struct JwsVerifier: Sendable {
    private let jwksUri: @Sendable () async throws -> String?
    private let allowedAlgorithms: @Sendable () async throws -> [String]
    private let jwks: JwksClient

    /// - Parameters:
    ///   - jwksUri: the `jwks_uri` from discovery, nil when the provider advertises none. A
    ///     closure because discovery is lazy and owned by another component.
    ///   - allowedAlgorithms: the provider's `id_token_signing_alg_values_supported`; empty means
    ///     it did not say, and the closed asymmetric set alone applies.
    public init(
        jwksUri: @escaping @Sendable () async throws -> String?,
        allowedAlgorithms: @escaping @Sendable () async throws -> [String],
        jwks: JwksClient
    ) {
        self.jwksUri = jwksUri
        self.allowedAlgorithms = allowedAlgorithms
        self.jwks = jwks
    }

    /// - Returns: the parsed token, whose payload is now trustworthy.
    /// - Throws: `JwsRejection` (`.malformed`, `.algorithm` or `.signature`);
    ///   `OAuthError.configuration(.providerUnsupported(capability: "jwks_uri"))` when discovery
    ///   has no `jwks_uri`; `OAuthError.recoverable` when the key set cannot be fetched.
    public func verify(_ compact: String) async throws -> ParsedJws {
        let token = try Jws.parse(compact)
        guard let algorithm = token.alg.flatMap(JwsAlgorithm.init(rawValue:)) else {
            throw JwsRejection(.algorithm, "alg is not in the closed asymmetric set")
        }
        let advertised = try await allowedAlgorithms()
        if !advertised.isEmpty && !advertised.contains(algorithm.rawValue) {
            throw JwsRejection(.algorithm, "alg is not advertised by the provider")
        }
        guard let uri = try await jwksUri() else {
            throw OAuthError.configuration(.providerUnsupported(capability: "jwks_uri"))
        }

        var loaded = try await jwks.keys(uri: uri, forceRefresh: false)
        if try Self.someKeyVerifies(token, algorithm, loaded.keys) { return token }
        if !loaded.fetched {
            // One refetch, and only when the set in hand was not itself just fetched: a cold
            // start that found no such key has already asked the provider, and a second miss
            // after a forced fetch is final, so a flood of unknown `kid`s costs at most one
            // request each and never a loop.
            loaded = try await jwks.keys(uri: uri, forceRefresh: true)
            if try Self.someKeyVerifies(token, algorithm, loaded.keys) { return token }
        }
        throw JwsRejection(.signature, "no key at jwks_uri verifies the signature")
    }

    private static func someKeyVerifies(_ token: ParsedJws, _ algorithm: JwsAlgorithm, _ set: JsonWebKeySet) throws -> Bool {
        try select(set, token, algorithm).contains {
            JwsSignatures.verifies(algorithm: algorithm, key: $0, signingInput: token.signingInput, signature: token.signature)
        }
    }

    /// The keys that could have signed `token`: right type, usable for signing, not pinned to
    /// another `alg`, suited to the algorithm's curve or size, and matching `kid` when the token
    /// names one. Without a `kid` more than one candidate is ambiguous and is refused outright (a
    /// refetch would not make it less so).
    private static func select(_ set: JsonWebKeySet, _ token: ParsedJws, _ algorithm: JwsAlgorithm) throws -> [JsonWebKey] {
        let suitable = set.keys.filter { key in
            key.kty == algorithm.keyType
                && (key.use == nil || key.use == "sig")
                && (key.alg == nil || key.alg == algorithm.rawValue)
                && JwsSignatures.suits(key, algorithm)
        }
        if let kid = token.kid { return suitable.filter { $0.kid == kid } }
        if suitable.count > 1 {
            throw JwsRejection(.signature, "token has no kid and several keys could have signed it")
        }
        return suitable
    }
}

// MARK: - Private helpers
// Named so they cannot collide with the shared Base64Url / SecureTokens the integrator adds;
// they are deduplicated then.

/// base64url without padding (RFC 7515 2), decoded strictly: only the URL-safe alphabet, and
/// optional trailing `=` the way `java.util.Base64`'s URL decoder takes it.
enum JoseBase64Url {
    private static let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".utf8)

    static func encode(_ data: Data) -> String {
        let bytes = Array(data)
        var out = [UInt8]()
        out.reserveCapacity((bytes.count * 4 + 2) / 3)
        var i = 0
        while i < bytes.count {
            let b0 = bytes[i]
            let b1: UInt8? = i + 1 < bytes.count ? bytes[i + 1] : nil
            let b2: UInt8? = i + 2 < bytes.count ? bytes[i + 2] : nil
            out.append(alphabet[Int(b0 >> 2)])
            out.append(alphabet[Int((b0 & 0x03) << 4 | (b1 ?? 0) >> 4)])
            if let b1 { out.append(alphabet[Int((b1 & 0x0F) << 2 | (b2 ?? 0) >> 6)]) }
            if let b2 { out.append(alphabet[Int(b2 & 0x3F)]) }
            i += 3
        }
        return String(decoding: out, as: UTF8.self)
    }

    /// Nil for anything that is not base64url.
    static func decode(_ string: String) -> Data? {
        var chars = Array(string.utf8)
        var padding = 0
        while chars.last == UInt8(ascii: "="), padding < 2 {
            chars.removeLast()
            padding += 1
        }
        if padding > 0 && (chars.count + padding) % 4 != 0 { return nil }
        if chars.count % 4 == 1 { return nil }
        var out = [UInt8]()
        out.reserveCapacity(chars.count * 3 / 4)
        var buffer: UInt32 = 0
        var bits = 0
        for c in chars {
            let value: UInt32
            switch c {
            case UInt8(ascii: "A")...UInt8(ascii: "Z"): value = UInt32(c - UInt8(ascii: "A"))
            case UInt8(ascii: "a")...UInt8(ascii: "z"): value = UInt32(c - UInt8(ascii: "a")) + 26
            case UInt8(ascii: "0")...UInt8(ascii: "9"): value = UInt32(c - UInt8(ascii: "0")) + 52
            case UInt8(ascii: "-"): value = 62
            case UInt8(ascii: "_"): value = 63
            default: return nil
            }
            buffer = (buffer << 6) | value
            bits += 6
            if bits >= 8 {
                bits -= 8
                out.append(UInt8((buffer >> UInt32(bits)) & 0xFF))
            }
        }
        return Data(out)
    }
}

/// A compare with no early exit, for a nonce or a hash that rode the wire (`security.md`).
enum JoseConstantTime {
    static func equals(_ a: String, _ b: String) -> Bool {
        let x = Array(a.utf8), y = Array(b.utf8)
        var diff = UInt8(truncatingIfNeeded: x.count ^ y.count)
        for i in 0..<max(x.count, y.count) {
            diff |= (i < x.count ? x[i] : 0) ^ (i < y.count ? y[i] : 0)
        }
        return diff == 0 && x.count == y.count
    }
}

/// Just enough DER to hand Security.framework a PKCS#1 RSAPublicKey.
enum DER {
    static func stripLeadingZeros(_ bytes: Data) -> [UInt8] {
        let array = Array(bytes)
        let start = array.firstIndex(where: { $0 != 0 }) ?? max(array.count - 1, 0)
        return Array(array[start...])
    }

    /// An unsigned big-endian value as a minimal, non-negative INTEGER: leading zeros dropped,
    /// one 0x00 put back when the top bit is set (otherwise DER reads it as negative).
    static func integer(_ unsigned: Data) -> [UInt8] {
        var value = stripLeadingZeros(unsigned)
        if value.isEmpty { value = [0] }
        if value[0] & 0x80 != 0 { value.insert(0, at: 0) }
        return [0x02] + length(value.count) + value
    }

    static func sequence(_ body: [UInt8]) -> Data {
        Data([0x30] + length(body.count) + body)
    }

    private static func length(_ count: Int) -> [UInt8] {
        switch count {
        case ..<0x80: return [UInt8(count)]
        case ..<0x100: return [0x81, UInt8(count)]
        case ..<0x10000: return [0x82, UInt8(count >> 8), UInt8(count & 0xFF)]
        default: return [0x83, UInt8(count >> 16), UInt8((count >> 8) & 0xFF), UInt8(count & 0xFF)]
        }
    }
}

/// A parsed JSON value that keeps what the claims checks need: a number is an integer or a
/// double, a boolean is not a number, and rendering back to text is deterministic. Parsed with
/// `JSONDecoder` (which bounds nesting) rather than by hand, because the input is a provider's
/// and, in a signed UserInfo response, not yet trusted.
enum JoseJSON: Sendable, Equatable, Decodable {
    case null
    case bool(Bool)
    case integer(Int64)
    case number(Double)
    case string(String)
    case array([JoseJSON])
    case object([String: JoseJSON])

    private struct Key: CodingKey {
        var stringValue: String
        var intValue: Int? { nil }
        init?(stringValue: String) { self.stringValue = stringValue }
        init?(intValue: Int) { return nil }
    }

    init(from decoder: Decoder) throws {
        if let keyed = try? decoder.container(keyedBy: Key.self) {
            var members = [String: JoseJSON]()
            for key in keyed.allKeys { members[key.stringValue] = try keyed.decode(JoseJSON.self, forKey: key) }
            self = .object(members)
        } else if var unkeyed = try? decoder.unkeyedContainer() {
            var items = [JoseJSON]()
            while !unkeyed.isAtEnd { items.append(try unkeyed.decode(JoseJSON.self)) }
            self = .array(items)
        } else {
            let single = try decoder.singleValueContainer()
            if single.decodeNil() {
                self = .null
            } else if let value = try? single.decode(Bool.self) {
                self = .bool(value)
            } else if let value = try? single.decode(Int64.self) {
                self = .integer(value)
            } else if let value = try? single.decode(Double.self) {
                self = .number(value)
            } else {
                self = .string(try single.decode(String.self))
            }
        }
    }

    /// Nil when `data` is not JSON.
    static func parse(_ data: Data) -> JoseJSON? {
        try? JSONDecoder().decode(JoseJSON.self, from: data)
    }

    /// The numeric value of an integer or a double; booleans and strings are not numbers.
    var numeric: Double? {
        switch self {
        case .integer(let value): return Double(value)
        case .number(let value): return value
        default: return nil
        }
    }

    /// A claim as the text the read-only maps promise: a string verbatim (no quotes), anything
    /// else as compact JSON. Same rule as Android's `asText`.
    var claimText: String {
        if case .string(let value) = self { return value }
        return compact
    }

    /// Compact JSON, keys sorted so that the same claim renders the same way every time.
    var compact: String {
        switch self {
        case .null: return "null"
        case .bool(let value): return value ? "true" : "false"
        case .integer(let value): return String(value)
        case .number(let value):
            if value.isFinite, value == value.rounded(), abs(value) < 1e15 { return String(Int64(value)) }
            return "\(value)"
        case .string(let value): return Self.quote(value)
        case .array(let items): return "[" + items.map { $0.compact }.joined(separator: ",") + "]"
        case .object(let members):
            return "{" + members.keys.sorted().map { Self.quote($0) + ":" + members[$0]!.compact }.joined(separator: ",") + "}"
        }
    }

    private static func quote(_ text: String) -> String {
        var out = "\""
        for scalar in text.unicodeScalars {
            switch scalar {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            case "\n": out += "\\n"
            case "\r": out += "\\r"
            case "\t": out += "\\t"
            case _ where scalar.value < 0x20: out += String(format: "\\u%04x", scalar.value)
            default: out.unicodeScalars.append(scalar)
            }
        }
        return out + "\""
    }
}
