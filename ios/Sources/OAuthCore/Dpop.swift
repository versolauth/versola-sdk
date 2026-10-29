import CryptoKit
import Foundation

/// The key a DPoP proof is signed with. The core never sees private material: the facade
/// supplies a Secure Enclave key (or the software fallback below) behind this seam.
public protocol DpopSigningKey: Sendable {
    /// The public half: `kty` `EC`, `crv` `P-256`, `x` and `y` base64url.
    func publicJwk() async throws -> JsonWebKey
    /// ES256 over `data`: the raw `R || S`, 64 bytes (RFC 7515 A.3.1), which is what
    /// `signature(for:).rawRepresentation` already is on CryptoKit.
    func sign(_ data: Data) async throws -> Data
}

/// A DPoP key held in process memory, for tests and for the software fallback when the device
/// has no Secure Enclave. The Secure Enclave key lives in the facade target, not here.
///
/// A software key is a fact to report, not an error to hide (`security.md`): whoever builds on
/// this decides whether the app accepts that tier.
public struct SoftwareDpopKey: DpopSigningKey {
    private let privateKey: P256.Signing.PrivateKey

    public init() {
        privateKey = P256.Signing.PrivateKey()
    }

    public init(privateKey: P256.Signing.PrivateKey) {
        self.privateKey = privateKey
    }

    public func publicJwk() async throws -> JsonWebKey {
        // x963 is 0x04 || X || Y, each coordinate 32 bytes.
        let point = privateKey.publicKey.x963Representation
        return JsonWebKey(
            kty: "EC",
            crv: "P-256",
            x: JoseBase64Url.encode(point.subdata(in: 1..<33)),
            y: JoseBase64Url.encode(point.subdata(in: 33..<65))
        )
    }

    public func sign(_ data: Data) async throws -> Data {
        try privateKey.signature(for: data).rawRepresentation
    }
}

/// How the origin of a URL is spelled for the per-origin nonce cache: scheme, host and port,
/// lower-cased, default port dropped. Shared by every caller that reads or writes a nonce, so
/// `https://host` and `https://host:443` are one entry and cannot alternate challenges.
public enum DpopOrigin {
    /// `scheme://host[:port]` of `url`. A URL without a scheme or host has no origin; the result
    /// is then the empty string, which no real origin equals.
    public static func of(_ url: URL) -> String {
        guard let parts = DpopURL.parts(url) else { return "" }
        let defaultPort = parts.scheme == "https" ? 443 : (parts.scheme == "http" ? 80 : -1)
        let port = parts.port.flatMap { $0 == defaultPort ? nil : ":\($0)" } ?? ""
        return "\(parts.scheme)://\(parts.host)\(port)"
    }
}

/// The split of a request URL that both the origin and `htu` are built from.
enum DpopURL {
    struct Parts {
        let scheme: String
        let host: String
        let port: Int?
        /// As it went on the wire: decoding first would collapse `/a%2Fb` and `/a/b` into one
        /// string, which is exactly the confusion `htu` exists to rule out.
        let rawPath: String
    }

    static func parts(_ url: URL) -> Parts? {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let scheme = components.scheme?.lowercased(),
              let rawHost = components.percentEncodedHost, !rawHost.isEmpty
        else { return nil }
        // Whether URLComponents hands back an IPv6 literal with its brackets has varied by OS
        // version; an authority needs them, so they are normalised here either way.
        let bare = rawHost.trimmingCharacters(in: CharacterSet(charactersIn: "[]")).lowercased()
        let host = bare.contains(":") ? "[\(bare)]" : bare
        return Parts(scheme: scheme, host: host, port: components.port, rawPath: components.percentEncodedPath)
    }
}

/// Mints RFC 9449 proofs: one per request, signed by the one key this installation holds.
///
/// Holds the nonce cache because a proof needs it and it belongs to no single request. Performs
/// no HTTP itself: the token client and the authenticated session call `proof` on the way out
/// and `observe` on the way back.
public actor DpopProofFactory: DpopProofSource {
    private let key: DpopSigningKey
    private let clock: Clock
    private let random: RandomSource
    /// Per origin and in memory only (`spec/state-machine.md`, persistence summary): a nonce is
    /// short-lived server state, and a stale one restored from disk buys a guaranteed extra round
    /// trip rather than saving one.
    private var nonces: [String: String] = [:]

    public init(key: DpopSigningKey, clock: Clock = .system, random: RandomSource = SystemRandomSource()) {
        self.key = key
        self.clock = clock
        self.random = random
    }

    /// RFC 7638 SHA-256 thumbprint of the public key, base64url: the `dpop_jkt` of an
    /// authorization request and the `jkt` a resource server compares.
    public func thumbprint() async throws -> String {
        let jwk = try await canonicalJwk()
        return JoseBase64Url.encode(Data(SHA256.hash(data: Data(jwk.compact.utf8))))
    }

    /// A proof for one request.
    ///
    /// - Parameters:
    ///   - nonce: the origin's remembered nonce, when it has issued one (`nonce(for:)`).
    ///   - accessToken: adds the section 4.2 `ath` binding. Required by a resource server and
    ///     impossible at the token endpoint, which has no token yet to hash, so its presence is
    ///     decided by the caller having one.
    public func proof(method: String, url: URL, nonce: String?, accessToken: String?) async throws -> String {
        guard let parts = DpopURL.parts(url) else {
            throw OAuthError.configuration(.invalidConfiguration(detail: "a DPoP request URL must be absolute with a host"))
        }
        let jwk = try await canonicalJwk()
        // The header carries the public key only; the canonical form has no private members, no
        // `kid`, no `alg` and no `use`, which RFC 9449 4.2 forbids a private key in and which
        // would only be noise otherwise.
        let header = JoseJSON.object([
            "typ": .string("dpop+jwt"),
            "alg": .string("ES256"),
            "jwk": jwk,
        ])
        // `htu` is the target URI without query and fragment (4.3 step 9). Stripping them here
        // keeps the claim equal to what the server reconstructs, and keeps query parameters,
        // which can carry identifiers, out of a token the server logs. Userinfo is dropped for
        // the same reason.
        let port = parts.port.map { ":\($0)" } ?? ""
        var claims: [String: JoseJSON] = [
            "htm": .string(method.uppercased()),
            "htu": .string("\(parts.scheme)://\(parts.host)\(port)\(parts.rawPath)"),
            "iat": .integer(Int64(clock.now().timeIntervalSince1970.rounded(.down))),
            // 128 bits from the CSPRNG: a proof must never be replayable under another jti.
            "jti": .string(JoseBase64Url.encode(Data(random.bytes(16)))),
        ]
        if let nonce, !nonce.isEmpty { claims["nonce"] = .string(nonce) }
        // 4.2: `base64url(SHA-256(ASCII(access token)))`.
        if let accessToken { claims["ath"] = .string(JoseBase64Url.encode(Data(SHA256.hash(data: Data(accessToken.utf8))))) }

        let signingInput = JoseBase64Url.encode(Data(header.compact.utf8)) + "." + JoseBase64Url.encode(Data(JoseJSON.object(claims).compact.utf8))
        let signature = try await key.sign(Data(signingInput.utf8))
        // Fail closed: a key that returns anything but R || S (a DER signature, say) would
        // produce a proof every server refuses, and the cause belongs here, not in a 401.
        guard signature.count == 64 else {
            throw OAuthError.configuration(.invalidConfiguration(detail: "the DPoP key did not return a 64-byte ES256 signature"))
        }
        return signingInput + "." + JoseBase64Url.encode(signature)
    }

    /// Remembers the nonce an origin demanded (`use_dpop_nonce`) or handed out. `origin` is
    /// `DpopOrigin.of(_:)`; an empty nonce is not a nonce.
    public func observe(nonce: String, origin: String) async {
        if !nonce.isEmpty { nonces[origin] = nonce }
    }

    public func nonce(for origin: String) async -> String? { nonces[origin] }

    /// Logout wipes the nonces along with everything else credential-shaped.
    public func clearNonces() async { nonces.removeAll() }

    /// The public JWK in RFC 7638's canonical form: required members only, lexicographic order,
    /// no whitespace. `JoseJSON.compact` sorts keys, which is that order here (`crv`, `kty`,
    /// `x`, `y`). A key that is not P-256 is refused: ES256 is the only algorithm this factory
    /// signs, and a proof whose `alg` does not match its key is one every server refuses.
    private func canonicalJwk() async throws -> JoseJSON {
        let jwk = try await key.publicJwk()
        guard jwk.kty == "EC", jwk.crv == "P-256",
              let x = jwk.x, let y = jwk.y,
              JoseBase64Url.decode(x)?.count == 32, JoseBase64Url.decode(y)?.count == 32
        else {
            throw OAuthError.configuration(.invalidConfiguration(detail: "the DPoP key is not an EC P-256 key"))
        }
        return .object(["kty": .string("EC"), "crv": .string("P-256"), "x": .string(x), "y": .string(y)])
    }
}
