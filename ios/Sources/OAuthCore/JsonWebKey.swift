import Foundation

/// One key of a JWKS (RFC 7517), as far as selecting a verification key needs: the type, the
/// `kid`, the pinned `alg`, the intended `use`, and the package key material by type. A key the
/// SDK cannot use (unknown `kty`, an unsupported curve) is skipped, never a failure of the set.
package struct JsonWebKey: Sendable, Equatable, Codable {
    package var kty: String
    package var kid: String?
    package var alg: String?
    package var use: String?
    /// RSA: base64url modulus and exponent.
    package var n: String?
    package var e: String?
    /// EC: curve name and base64url coordinates.
    package var crv: String?
    package var x: String?
    package var y: String?

    package init(kty: String, kid: String? = nil, alg: String? = nil, use: String? = nil, n: String? = nil, e: String? = nil, crv: String? = nil, x: String? = nil, y: String? = nil) {
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

package struct JsonWebKeySet: Sendable, Equatable, Codable {
    package var keys: [JsonWebKey]
    package init(keys: [JsonWebKey]) { self.keys = keys }
}
