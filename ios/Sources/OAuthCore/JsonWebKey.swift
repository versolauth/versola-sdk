import Foundation

/// One key of a JWKS (RFC 7517), as far as selecting a verification key needs: the type, the
/// `kid`, the pinned `alg`, the intended `use`, and the public key material by type. A key the
/// SDK cannot use (unknown `kty`, an unsupported curve) is skipped, never a failure of the set.
public struct JsonWebKey: Sendable, Equatable, Codable {
    public var kty: String
    public var kid: String?
    public var alg: String?
    public var use: String?
    /// RSA: base64url modulus and exponent.
    public var n: String?
    public var e: String?
    /// EC: curve name and base64url coordinates.
    public var crv: String?
    public var x: String?
    public var y: String?

    public init(kty: String, kid: String? = nil, alg: String? = nil, use: String? = nil, n: String? = nil, e: String? = nil, crv: String? = nil, x: String? = nil, y: String? = nil) {
        self.kty = kty
        self.kid = kid
        self.alg = alg
        self.use = use
        self.n = n
        self.e = e
        self.crv = crv
        self.x = x
        self.y = y
    }
}

public struct JsonWebKeySet: Sendable, Equatable, Codable {
    public var keys: [JsonWebKey]
    public init(keys: [JsonWebKey]) { self.keys = keys }
}
