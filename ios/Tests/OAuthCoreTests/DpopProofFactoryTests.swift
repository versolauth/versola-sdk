import CryptoKit
import Foundation
import XCTest
@testable import OAuthCore

/// A random source that counts up, so `jti` values are predictable and the test can see the
/// factory asked for 16 bytes.
private struct JoseCountingRandom: RandomSource {
    func bytes(_ count: Int) -> [UInt8] { [UInt8](repeating: 0xAB, count: count) }
}

/// A key that answers with whatever it is told to, to prove the factory fails closed.
private struct JoseBadKey: DpopSigningKey {
    let jwk: JsonWebKey
    let signature: Data
    func publicJwk() async throws -> JsonWebKey { jwk }
    func sign(_ data: Data) async throws -> Data { signature }
}

final class DpopProofFactoryTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 1_900_000_000.9)
    private let url = URL(string: "https://rs.example.com/resource/a%2Fb?filter=%7B1%7D&token=secret#frag")!

    private func factory(_ key: DpopSigningKey = SoftwareDpopKey(), random: RandomSource = SystemRandomSource()) -> DpopProofFactory {
        let at = now
        return DpopProofFactory(key: key, clock: Clock(now: { at }), random: random)
    }

    // MARK: thumbprint

    /// RFC 9449's example key (the one in its sample proof); the expected value was computed
    /// here with `openssl dgst -sha256` over the RFC 7638 canonical form, outside this code, and
    /// is the `jkt` that document prints for that key.
    func testThumbprintOfAKnownEcKeyMatchesTheIndependentlyComputedValue() async throws {
        let key = JoseBadKey(
            jwk: JsonWebKey(kty: "EC", kid: "ignored", alg: "ES256", use: "sig", crv: "P-256",
                            x: "l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs", y: "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA"),
            signature: Data(count: 64)
        )
        let thumbprint = try await factory(key).thumbprint()
        XCTAssertEqual(thumbprint, "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I")
    }

    func testThumbprintRecomputesFromTheCanonicalJwkAndIgnoresOptionalMembers() async throws {
        let software = SoftwareDpopKey()
        let jwk = try await software.publicJwk()
        let canonical = #"{"crv":"P-256","kty":"EC","x":"\#(jwk.x!)","y":"\#(jwk.y!)"}"#
        let expected = JoseBase64Url.encode(Data(SHA256.hash(data: Data(canonical.utf8))))

        let plain = try await factory(software).thumbprint()
        var decorated = jwk
        decorated.kid = "k1"
        decorated.alg = "ES256"
        decorated.use = "sig"
        let withExtras = try await factory(JoseBadKey(jwk: decorated, signature: Data())).thumbprint()

        XCTAssertEqual(plain, expected)
        XCTAssertEqual(withExtras, expected)
    }

    func testDifferentKeysHaveDifferentThumbprints() async throws {
        let a = try await factory().thumbprint()
        let b = try await factory().thumbprint()
        XCTAssertNotEqual(a, b)
    }

    // MARK: proof shape

    func testProofIsAnEs256DpopJwtWhoseSignatureVerifiesUnderTheKeyInItsOwnHeader() async throws {
        let proof = try await factory().proof(method: "get", url: url, nonce: nil, accessToken: nil)

        let decoded = JoseTestTokens.decode(proof)
        XCTAssertEqual(decoded.header["typ"] as? String, "dpop+jwt")
        XCTAssertEqual(decoded.header["alg"] as? String, "ES256")
        let jwk = try XCTUnwrap(decoded.header["jwk"] as? [String: Any])
        XCTAssertEqual(Set(jwk.keys), ["kty", "crv", "x", "y"], "the public key only, no kid, use or private members")
        XCTAssertEqual(jwk["kty"] as? String, "EC")
        XCTAssertEqual(jwk["crv"] as? String, "P-256")
        let key = JsonWebKey(kty: "EC", crv: "P-256", x: jwk["x"] as? String, y: jwk["y"] as? String)
        let signature = try XCTUnwrap(JoseBase64Url.decode(decoded.parts[2]))
        XCTAssertEqual(signature.count, 64)
        XCTAssertTrue(JwsSignatures.verifies(algorithm: .ES256, key: key, signingInput: Data("\(decoded.parts[0]).\(decoded.parts[1])".utf8), signature: signature))
        // And not under another key.
        let other = try await SoftwareDpopKey().publicJwk()
        XCTAssertFalse(JwsSignatures.verifies(algorithm: .ES256, key: other, signingInput: Data("\(decoded.parts[0]).\(decoded.parts[1])".utf8), signature: signature))
    }

    func testHtmIsUppercasedAndHtuDropsQueryAndFragmentButKeepsTheRawPath() async throws {
        let proof = try await factory().proof(method: "post", url: url, nonce: nil, accessToken: nil)
        let claims = JoseTestTokens.decode(proof).claims
        XCTAssertEqual(claims["htm"] as? String, "POST")
        XCTAssertEqual(claims["htu"] as? String, "https://rs.example.com/resource/a%2Fb")
        XCTAssertFalse(proof.contains("secret"))
    }

    func testHtuKeepsAnExplicitPortAndDropsUserinfo() async throws {
        let withPort = try await factory().proof(method: "GET", url: URL(string: "https://user:pw@Rs.Example.com:8443/x?q=1")!, nonce: nil, accessToken: nil)
        let claims = JoseTestTokens.decode(withPort).claims
        XCTAssertEqual(claims["htu"] as? String, "https://rs.example.com:8443/x")
        XCTAssertFalse(withPort.contains("pw"))
    }

    func testIatIsTheInjectedClockInWholeSecondsAndJtiIs128BitsOfTheInjectedRandomSource() async throws {
        let proof = try await factory(random: JoseCountingRandom()).proof(method: "GET", url: url, nonce: nil, accessToken: nil)
        let claims = JoseTestTokens.decode(proof).claims
        XCTAssertEqual(claims["iat"] as? Int, 1_900_000_000)
        XCTAssertEqual(claims["jti"] as? String, JoseBase64Url.encode(Data(repeating: 0xAB, count: 16)))
    }

    func testEveryProofCarriesADifferentJti() async throws {
        let subject = factory()
        var seen = Set<String>()
        for _ in 0..<50 {
            let proof = try await subject.proof(method: "GET", url: url, nonce: nil, accessToken: nil)
            seen.insert(JoseTestTokens.decode(proof).claims["jti"] as! String)
        }
        XCTAssertEqual(seen.count, 50)
    }

    func testAthIsPresentOnlyWithATokenAndIsTheSha256OfIt() async throws {
        let subject = factory()
        let without = try await subject.proof(method: "GET", url: url, nonce: nil, accessToken: nil)
        let with = try await subject.proof(method: "GET", url: url, nonce: nil, accessToken: "access-1")
        XCTAssertNil(JoseTestTokens.decode(without).claims["ath"])
        XCTAssertEqual(JoseTestTokens.decode(with).claims["ath"] as? String, JoseBase64Url.encode(Data(SHA256.hash(data: Data("access-1".utf8)))))
    }

    func testNonceClaimIsPresentOnlyWhenGiven() async throws {
        let subject = factory()
        let without = try await subject.proof(method: "GET", url: url, nonce: nil, accessToken: nil)
        let empty = try await subject.proof(method: "GET", url: url, nonce: "", accessToken: nil)
        let with = try await subject.proof(method: "GET", url: url, nonce: "n-1", accessToken: nil)
        XCTAssertNil(JoseTestTokens.decode(without).claims["nonce"])
        XCTAssertNil(JoseTestTokens.decode(empty).claims["nonce"])
        XCTAssertEqual(JoseTestTokens.decode(with).claims["nonce"] as? String, "n-1")
    }

    // MARK: fail closed

    func testKeyThatIsNotP256IsRefused() async {
        let p384 = JoseTestKeys.p384.jwk(kid: nil)
        let rsa = JoseTestKeys.rsa.jwk(kid: nil)
        for jwk in [p384, rsa, JsonWebKey(kty: "EC", crv: "P-256", x: "AAAA", y: "AAAA"), JsonWebKey(kty: "EC", crv: "P-256")] {
            let subject = factory(JoseBadKey(jwk: jwk, signature: Data(count: 64)))
            let proofError = await joseThrown { _ = try await subject.proof(method: "GET", url: url, nonce: nil, accessToken: nil) }
            let thumbprintError = await joseThrown { _ = try await subject.thumbprint() }
            for error in [proofError, thumbprintError] {
                guard case .configuration(.invalidConfiguration)? = error as? OAuthError else { return XCTFail("\(String(describing: error))") }
            }
        }
    }

    func testKeyThatDoesNotReturnA64ByteSignatureIsRefused() async throws {
        let jwk = try await SoftwareDpopKey().publicJwk()
        for signature in [Data(), Data(count: 63), Data(count: 72)] {
            let subject = factory(JoseBadKey(jwk: jwk, signature: signature))
            let error = await joseThrown { _ = try await subject.proof(method: "GET", url: url, nonce: nil, accessToken: nil) }
            guard case .configuration(.invalidConfiguration)? = error as? OAuthError else { return XCTFail("\(String(describing: error))") }
        }
    }

    func testUrlWithoutAHostIsRefused() async {
        let error = await joseThrown { _ = try await factory().proof(method: "GET", url: URL(string: "/relative")!, nonce: nil, accessToken: nil) }
        guard case .configuration(.invalidConfiguration)? = error as? OAuthError else { return XCTFail("\(String(describing: error))") }
    }

    // MARK: nonces per origin

    func testNoncesAreKeptPerOriginAndClearedTogether() async {
        let subject = factory()
        await subject.observe(nonce: "auth-nonce", origin: "https://auth.example.com")
        await subject.observe(nonce: "edge-nonce", origin: "https://edge.example.com")
        await subject.observe(nonce: "", origin: "https://other.example.com")

        let auth = await subject.nonce(for: "https://auth.example.com")
        let edge = await subject.nonce(for: "https://edge.example.com")
        let other = await subject.nonce(for: "https://other.example.com")
        XCTAssertEqual(auth, "auth-nonce")
        XCTAssertEqual(edge, "edge-nonce")
        XCTAssertNil(other, "an empty nonce is not a nonce")

        await subject.observe(nonce: "auth-nonce-2", origin: "https://auth.example.com")
        let replaced = await subject.nonce(for: "https://auth.example.com")
        XCTAssertEqual(replaced, "auth-nonce-2")

        await subject.clearNonces()
        let afterAuth = await subject.nonce(for: "https://auth.example.com")
        let afterEdge = await subject.nonce(for: "https://edge.example.com")
        XCTAssertNil(afterAuth)
        XCTAssertNil(afterEdge)
    }

    func testOriginIsSchemeHostAndPortWithTheDefaultPortAndCaseNormalisedAway() {
        func origin(_ text: String) -> String { DpopOrigin.of(URL(string: text)!) }
        XCTAssertEqual(origin("https://Auth.Example.com/path?q=1"), "https://auth.example.com")
        XCTAssertEqual(origin("https://auth.example.com:443/other"), "https://auth.example.com")
        XCTAssertEqual(origin("http://auth.example.com:80"), "http://auth.example.com")
        XCTAssertEqual(origin("https://auth.example.com:8443/x"), "https://auth.example.com:8443")
        XCTAssertEqual(origin("http://localhost:8080/x"), "http://localhost:8080")
        XCTAssertEqual(origin("http://[::1]:8080/x"), "http://[::1]:8080")
        XCTAssertEqual(origin("https://user:pw@auth.example.com/x"), "https://auth.example.com")
        XCTAssertNotEqual(origin("https://auth.example.com"), origin("https://edge.example.com"))
        XCTAssertNotEqual(origin("https://a.example.com:8443"), origin("https://a.example.com:9443"))
        XCTAssertEqual(DpopOrigin.of(URL(string: "/relative")!), "")
    }
}
