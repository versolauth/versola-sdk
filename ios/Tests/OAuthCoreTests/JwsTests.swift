import Foundation
import XCTest
@testable import OAuthCore

final class JwsTests: XCTestCase {
    private let payload = #"{"sub":"u1"}"#

    private func rejection(of compact: String, file: StaticString = #filePath, line: UInt = #line) -> IdTokenRejection? {
        do {
            _ = try Jws.parse(compact)
            XCTFail("expected a rejection", file: file, line: line)
            return nil
        } catch let rejection as JwsRejection {
            return rejection.reason
        } catch {
            XCTFail("unexpected error \(error)", file: file, line: line)
            return nil
        }
    }

    private func segment(_ text: String) -> String { JoseBase64Url.encode(Data(text.utf8)) }

    private func verifies(_ alg: String, _ token: String, key: JsonWebKey) -> Bool {
        let parsed = try! Jws.parse(token)
        return JwsSignatures.verifies(algorithm: JwsAlgorithm(rawValue: alg)!, key: key, signingInput: parsed.signingInput, signature: parsed.signature)
    }

    // MARK: parsing

    func testCompactJwsIsSplitAndAlgKidTypAreRead() throws {
        let token = try Jws.parse(JoseTestTokens.rsa("RS256", payload: payload, kid: "k1"))
        XCTAssertEqual(token.alg, "RS256")
        XCTAssertEqual(token.kid, "k1")
        XCTAssertEqual(token.typ, "JWT")
        XCTAssertEqual(token.claims["sub"], .string("u1"))
        XCTAssertEqual(String(decoding: token.payload, as: UTF8.self), payload)
        XCTAssertEqual(token.description, "ParsedJws(redacted)")
    }

    func testTokenWithTwoSegmentsIsMalformed() {
        XCTAssertEqual(rejection(of: "aaa.bbb"), .malformed)
    }

    func testTokenWithFourSegmentsIsMalformed() {
        XCTAssertEqual(rejection(of: "a.b.c.d"), .malformed)
    }

    func testEmptyStringAndSingleDotsAreMalformed() {
        for text in ["", ".", "..", "a.."] { XCTAssertEqual(rejection(of: text), .malformed, text) }
    }

    func testSegmentThatIsNotBase64urlIsMalformed() {
        XCTAssertEqual(rejection(of: "!!!." + segment(payload) + ".AAAA"), .malformed)
        XCTAssertEqual(rejection(of: segment(#"{"alg":"RS256"}"#) + "." + segment(payload) + ".AA AA"), .malformed)
        XCTAssertEqual(rejection(of: segment(#"{"alg":"RS256"}"#) + "." + segment(payload) + ".A"), .malformed)
    }

    func testHeaderThatIsNotJsonIsMalformed() {
        XCTAssertEqual(rejection(of: segment("not json") + "." + segment(payload) + ".AAAA"), .malformed)
    }

    func testHeaderThatIsNotAnObjectIsMalformed() {
        XCTAssertEqual(rejection(of: segment(#"["RS256"]"#) + "." + segment(payload) + ".AAAA"), .malformed)
        XCTAssertEqual(rejection(of: segment(#""RS256""#) + "." + segment(payload) + ".AAAA"), .malformed)
    }

    func testPayloadThatIsNotAnObjectIsMalformed() {
        XCTAssertEqual(rejection(of: segment(#"{"alg":"RS256"}"#) + "." + segment("[1]") + ".AAAA"), .malformed)
    }

    func testHeaderWithoutStringAlgIsMalformed() {
        XCTAssertEqual(rejection(of: segment(#"{"alg":5}"#) + "." + segment(payload) + ".AAAA"), .malformed)
        XCTAssertEqual(rejection(of: segment(#"{"typ":"JWT"}"#) + "." + segment(payload) + ".AAAA"), .malformed)
    }

    func testHeaderWithCritExtensionIsRefusedBecauseNoneIsUnderstood() {
        let header = #"{"alg":"RS256","crit":["exp"],"exp":1}"#
        let token = JoseTestTokens.jws(header: header, payload: payload, sign: { JoseTestKeys.rsa.sign("RS256", $0) })
        XCTAssertEqual(rejection(of: token), .malformed)
    }

    func testDeeplyNestedPayloadIsMalformedAndDoesNotCrash() {
        let nested = String(repeating: "[", count: 5000) + String(repeating: "]", count: 5000)
        XCTAssertEqual(rejection(of: segment(#"{"alg":"RS256"}"#) + "." + segment(#"{"a":"# + nested + "}") + ".AAAA"), .malformed)
    }

    func testNoGeneratedGarbageCrashesTheParser() {
        var generator = SystemRandomNumberGenerator()
        let alphabet = Array("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_=.{}[]\"\\ ")
        for _ in 0..<500 {
            let length = Int.random(in: 0..<80, using: &generator)
            let text = String((0..<length).map { _ in alphabet.randomElement(using: &generator)! })
            _ = try? Jws.parse(text)
        }
    }

    // MARK: the algorithm set

    func testNoneAndHmacAlgorithmsAreNotInTheClosedSet() {
        for name in ["none", "HS256", "HS384", "HS512", "RS1", "ES256K", "EdDSA", "rs256"] {
            XCTAssertNil(JwsAlgorithm(rawValue: name), name)
        }
        XCTAssertEqual(Set(JwsAlgorithm.allCases.map(\.rawValue)), ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"])
    }

    // MARK: RSA

    func testRS256RS384AndRS512SignaturesVerifyUnderTheRsaKey() {
        for alg in ["RS256", "RS384", "RS512"] {
            let token = JoseTestTokens.rsa(alg, payload: payload)
            XCTAssertTrue(verifies(alg, token, key: JoseTestKeys.rsa.jwk(kid: "rsa")), alg)
        }
    }

    func testPS256PS384AndPS512SignaturesVerifyUnderTheRsaKey() {
        for alg in ["PS256", "PS384", "PS512"] {
            let token = JoseTestTokens.rsa(alg, payload: payload)
            XCTAssertTrue(verifies(alg, token, key: JoseTestKeys.rsa.jwk(kid: "rsa")), alg)
        }
    }

    /// Independent of Security.framework's signer: made with `openssl dgst -sigopt rsa_pss_saltlen:digest`
    /// and `-sigopt rsa_mgf1_md`, i.e. RFC 7518 3.5 (MGF1 with the same digest, salt as long as the
    /// digest). Proves the PSS parameters Security.framework verifies with are JOSE's, not only
    /// that it agrees with itself. Key and signatures are generated and throwaway.
    func testOpenSslProducedRsaPssAndPkcs1SignaturesVerify() {
        let key = JsonWebKey(kty: "RSA", kid: "fx", n: JwsTests.fixtureN, e: "AQAB")
        let input = Data("eyJhbGciOiJQUzI1NiJ9.eyJzdWIiOiJ1MSJ9".utf8)
        for (alg, signature) in JwsTests.fixtureSignatures {
            let bytes = JoseBase64Url.decode(signature)!
            XCTAssertTrue(JwsSignatures.verifies(algorithm: JwsAlgorithm(rawValue: alg)!, key: key, signingInput: input, signature: bytes), alg)
            var flipped = bytes
            flipped[flipped.count / 2] ^= 0x01
            XCTAssertFalse(JwsSignatures.verifies(algorithm: JwsAlgorithm(rawValue: alg)!, key: key, signingInput: input, signature: flipped), "flipped \(alg)")
        }
    }

    func testFlippedSignatureByteDoesNotVerifyForEveryAlgorithm() {
        let rsaKey = JoseTestKeys.rsa.jwk(kid: "rsa")
        for alg in ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"] {
            let parsed = try! Jws.parse(JoseTestTokens.rsa(alg, payload: payload))
            var signature = parsed.signature
            signature[signature.count - 1] ^= 0x01
            XCTAssertFalse(JwsSignatures.verifies(algorithm: JwsAlgorithm(rawValue: alg)!, key: rsaKey, signingInput: parsed.signingInput, signature: signature), alg)
        }
        for key in [JoseTestKeys.p256, JoseTestKeys.p384, JoseTestKeys.p521] {
            let parsed = try! Jws.parse(JoseTestTokens.ec(key, payload: payload, kid: nil))
            var signature = parsed.signature
            signature[5] ^= 0x01
            XCTAssertFalse(JwsSignatures.verifies(algorithm: JwsAlgorithm(rawValue: key.alg)!, key: key.jwk(kid: nil), signingInput: parsed.signingInput, signature: signature), key.alg)
        }
    }

    func testSignatureMadeByAnotherRsaKeyDoesNotVerify() {
        let token = JoseTestTokens.rsa("RS256", JoseTestKeys.rsaOther, payload: payload)
        XCTAssertFalse(verifies("RS256", token, key: JoseTestKeys.rsa.jwk(kid: "rsa")))
    }

    func testPayloadChangedAfterSigningDoesNotVerify() throws {
        let parts = JoseTestTokens.rsa("RS256", payload: payload).split(separator: ".").map(String.init)
        let tampered = parts[0] + "." + segment(#"{"sub":"u2"}"#) + "." + parts[2]
        XCTAssertFalse(verifies("RS256", tampered, key: JoseTestKeys.rsa.jwk(kid: "rsa")))
    }

    func testRs256SignatureDoesNotVerifyAsPs256AndTheReverse() {
        let key = JoseTestKeys.rsa.jwk(kid: "rsa")
        XCTAssertFalse(verifies("PS256", JoseTestTokens.rsa("RS256", payload: payload), key: key))
        XCTAssertFalse(verifies("RS256", JoseTestTokens.rsa("PS256", payload: payload), key: key))
    }

    func testRsaKeyUnder2048BitsIsNotSuitableForAnyRsaAlgorithm() {
        let small = JoseTestRSAKey.generate(bits: 1024)
        for alg in ["RS256", "PS256"] {
            let token = JoseTestTokens.rsa(alg, small, payload: payload)
            XCTAssertFalse(verifies(alg, token, key: small.jwk(kid: "small")), alg)
        }
    }

    func testRsaKeyWithUnusableExponentIsRefused() {
        let token = JoseTestTokens.rsa("RS256", payload: payload)
        for exponent in ["AQ", "Ag", ""] {
            var key = JoseTestKeys.rsa.jwk(kid: "rsa")
            key.e = exponent
            XCTAssertFalse(verifies("RS256", token, key: key), "e=\(exponent)")
        }
    }

    func testRsaKeyWithMissingOrUndecodableMaterialIsRefusedWithoutCrashing() {
        let token = JoseTestTokens.rsa("RS256", payload: payload)
        var noModulus = JoseTestKeys.rsa.jwk(kid: "rsa")
        noModulus.n = nil
        var garbage = JoseTestKeys.rsa.jwk(kid: "rsa")
        garbage.n = "!!!"
        XCTAssertFalse(verifies("RS256", token, key: noModulus))
        XCTAssertFalse(verifies("RS256", token, key: garbage))
    }

    // MARK: EC

    func testES256ES384AndES512VerifyUnderTheP256P384AndP521Keys() {
        for key in [JoseTestKeys.p256, JoseTestKeys.p384, JoseTestKeys.p521] {
            let token = JoseTestTokens.ec(key, payload: payload, kid: nil)
            XCTAssertTrue(verifies(key.alg, token, key: key.jwk(kid: nil)), key.alg)
        }
    }

    func testManyES256SignaturesVerifyWhateverTheirLeadingZerosAndHighBits() {
        // R and S are random 256-bit integers; the shapes a DER conversion gets wrong (a leading
        // zero byte, a set top bit) are in the corpus. CryptoKit needs no conversion, and this
        // keeps it that way.
        let key = JoseTestKeys.p256.jwk(kid: nil)
        for index in 0..<300 {
            let token = JoseTestTokens.ec(JoseTestKeys.p256, payload: #"{"n":\#(index)}"#, kid: nil)
            XCTAssertTrue(verifies("ES256", token, key: key), "token \(index)")
        }
    }

    func testSignatureMadeByAnotherEcKeyDoesNotVerify() {
        let token = JoseTestTokens.ec(JoseTestKeys.p256Other, payload: payload, kid: nil)
        XCTAssertFalse(verifies("ES256", token, key: JoseTestKeys.p256.jwk(kid: nil)))
    }

    func testEs256IsRefusedWithAP384KeyAndWithARelabelledCurve() {
        let token = JoseTestTokens.ec(JoseTestKeys.p256, payload: payload, kid: nil)
        XCTAssertFalse(verifies("ES256", token, key: JoseTestKeys.p384.jwk(kid: nil)))
        // A P-384 key claiming to be P-256: the coordinate width gives it away.
        var relabelled = JoseTestKeys.p384.jwk(kid: nil)
        relabelled.crv = "P-256"
        XCTAssertFalse(verifies("ES256", token, key: relabelled))
        // And the reverse: a P-256 key under ES384.
        let es384 = JoseTestTokens.ec(JoseTestKeys.p384, payload: payload, kid: nil)
        XCTAssertFalse(verifies("ES384", es384, key: JoseTestKeys.p256.jwk(kid: nil)))
        XCTAssertFalse(verifies("ES512", es384, key: JoseTestKeys.p384.jwk(kid: nil)))
    }

    func testKeyOfTheWrongTypeForTheAlgorithmIsRefused() {
        let es = JoseTestTokens.ec(JoseTestKeys.p256, payload: payload, kid: nil)
        let rs = JoseTestTokens.rsa("RS256", payload: payload)
        XCTAssertFalse(verifies("ES256", es, key: JoseTestKeys.rsa.jwk(kid: nil)))
        XCTAssertFalse(verifies("RS256", rs, key: JoseTestKeys.p256.jwk(kid: nil)))
    }

    func testEs256SignatureOfTheWrongLengthDoesNotVerify() {
        let parsed = try! Jws.parse(JoseTestTokens.ec(JoseTestKeys.p256, payload: payload, kid: nil))
        let key = JoseTestKeys.p256.jwk(kid: nil)
        for length in [0, 63, 65, 96] {
            XCTAssertFalse(JwsSignatures.verifies(algorithm: .ES256, key: key, signingInput: parsed.signingInput, signature: Data(count: length)), "\(length) bytes")
        }
        // A DER signature is not a JOSE one.
        XCTAssertFalse(JwsSignatures.verifies(algorithm: .ES256, key: key, signingInput: parsed.signingInput, signature: Data([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01])))
    }

    func testRAndSOfZerosDoNotVerify() {
        let parsed = try! Jws.parse(JoseTestTokens.ec(JoseTestKeys.p256, payload: payload, kid: nil))
        XCTAssertFalse(JwsSignatures.verifies(algorithm: .ES256, key: JoseTestKeys.p256.jwk(kid: nil), signingInput: parsed.signingInput, signature: Data(count: 64)))
    }

    func testEcPointThatIsNotOnTheCurveIsRefused() {
        let token = JoseTestTokens.ec(JoseTestKeys.p256, payload: payload, kid: nil)
        var key = JoseTestKeys.p256.jwk(kid: nil)
        key.y = JoseBase64Url.encode(Data(repeating: 0x01, count: 32))
        XCTAssertFalse(verifies("ES256", token, key: key))
    }

    func testEcKeyWithMissingCoordinatesIsRefusedWithoutCrashing() {
        let token = JoseTestTokens.ec(JoseTestKeys.p256, payload: payload, kid: nil)
        var key = JoseTestKeys.p256.jwk(kid: nil)
        key.x = nil
        XCTAssertFalse(verifies("ES256", token, key: key))
        key = JoseTestKeys.p256.jwk(kid: nil)
        key.crv = nil
        XCTAssertFalse(verifies("ES256", token, key: key))
    }

    // MARK: helpers

    func testBase64UrlRoundTripsAndRefusesWhatIsNotBase64Url() {
        for length in 0..<40 {
            let data = Data((0..<length).map { UInt8(truncatingIfNeeded: $0 &* 37 &+ 11) })
            XCTAssertEqual(JoseBase64Url.decode(JoseBase64Url.encode(data)), data, "\(length)")
        }
        XCTAssertEqual(JoseBase64Url.decode("AAA="), Data([0, 0]))
        XCTAssertNil(JoseBase64Url.decode("A+B/"))
        XCTAssertNil(JoseBase64Url.decode("AA=A"))
        XCTAssertNil(JoseBase64Url.decode("A"))
        XCTAssertNil(JoseBase64Url.decode("AA A"))
        XCTAssertNil(JoseBase64Url.decode("\u{00e9}\u{00e9}"))
    }

    func testDerIntegerIsMinimalAndNonNegative() {
        XCTAssertEqual(DER.integer(Data([0x00, 0x00, 0x01])), [0x02, 0x01, 0x01])
        XCTAssertEqual(DER.integer(Data([0x80])), [0x02, 0x02, 0x00, 0x80])
        XCTAssertEqual(DER.integer(Data()), [0x02, 0x01, 0x00])
        XCTAssertEqual(Array(DER.sequence(DER.integer(Data(repeating: 0xFF, count: 300))).prefix(4)), [0x30, 0x82, 0x01, 0x31])  // 0x00 + 300 bytes, plus the 4-byte INTEGER header
    }

    func testConstantTimeEqualsComparesWholeValues() {
        XCTAssertTrue(JoseConstantTime.equals("abc", "abc"))
        XCTAssertFalse(JoseConstantTime.equals("abc", "abd"))
        XCTAssertFalse(JoseConstantTime.equals("abc", "ab"))
        XCTAssertFalse(JoseConstantTime.equals("ab", "abc"))
        XCTAssertTrue(JoseConstantTime.equals("", ""))
    }

    // MARK: the verifier

    private func verifier(allowed: [String] = [], jwksUri: String? = "https://issuer.example.com/jwks.json", stub: JoseStubHTTP) -> JwsVerifier {
        JwsVerifier(jwksUri: { jwksUri }, allowedAlgorithms: { allowed }, jwks: JwksClient(httpClient: stub))
    }

    private func reason(_ verifier: JwsVerifier, _ token: String) async -> IdTokenRejection? {
        let error = await joseThrown { _ = try await verifier.verify(token) }
        return (error as? JwsRejection)?.reason
    }

    func testAlgNoneIsRefusedAsAlgorithmBeforeAnyKeyIsFetched() async {
        let stub = JoseStubHTTP()
        let token = JoseTestTokens.jws(header: #"{"alg":"none","kid":"rsa"}"#, payload: payload, sign: nil)
        let result = await reason(verifier(stub: stub), token)
        let count = await stub.requestCount()
        XCTAssertEqual(result, .algorithm)
        XCTAssertEqual(count, 0)
    }

    func testHs256IsRefusedAsAlgorithmBeforeAnyKeyIsFetched() async {
        // The key-confusion attack: an HMAC keyed with the provider's public key bytes.
        let stub = JoseStubHTTP()
        let token = JoseTestTokens.jws(header: #"{"alg":"HS256","kid":"rsa"}"#, payload: payload, sign: { Data(repeating: 7, count: 32) + $0.prefix(1) })
        for alg in ["HS256", "HS384", "HS512", "ES256K", "RS1"] {
            let t = JoseTestTokens.jws(header: "{\"alg\":\"\(alg)\"}", payload: payload, sign: nil)
            let result = await reason(verifier(stub: stub), t)
            XCTAssertEqual(result, .algorithm, alg)
        }
        let result = await reason(verifier(stub: stub), token)
        let count = await stub.requestCount()
        XCTAssertEqual(result, .algorithm)
        XCTAssertEqual(count, 0)
    }

    func testAlgorithmTheProviderDoesNotAdvertiseIsRefusedBeforeAnyKeyIsFetched() async {
        let stub = JoseStubHTTP()
        let result = await reason(verifier(allowed: ["ES256"], stub: stub), JoseTestTokens.rsa("RS256", payload: payload))
        let count = await stub.requestCount()
        XCTAssertEqual(result, .algorithm)
        XCTAssertEqual(count, 0)
    }

    func testMalformedTokenIsRefusedWithoutANetworkRequest() async {
        let stub = JoseStubHTTP()
        let result = await reason(verifier(stub: stub), "not-a-jwt")
        let count = await stub.requestCount()
        XCTAssertEqual(result, .malformed)
        XCTAssertEqual(count, 0)
    }

    func testProviderWithoutAJwksUriIsProviderUnsupportedAndNothingIsFetched() async {
        let stub = JoseStubHTTP()
        let error = await joseThrown { _ = try await verifier(jwksUri: nil, stub: stub).verify(JoseTestTokens.rsa("RS256", payload: payload)) }
        let count = await stub.requestCount()
        XCTAssertEqual(error as? OAuthError, .configuration(.providerUnsupported(capability: "jwks_uri")))
        XCTAssertEqual(count, 0)
    }

    func testTokenSignedByAPublishedKeyVerifiesAndAForgeryIsRefusedAsSignature() async throws {
        let stub = JoseStubHTTP()
        await stub.enqueue("/jwks.json", body: JoseTestTokens.jwks(JoseTestKeys.rsa.jwk(kid: "rsa")))
        let subject = verifier(stub: stub)
        let good = try await subject.verify(JoseTestTokens.rsa("RS256", payload: payload))
        XCTAssertEqual(good.claims["sub"], .string("u1"))

        await stub.enqueue("/jwks.json", body: JoseTestTokens.jwks(JoseTestKeys.rsa.jwk(kid: "rsa")))
        let forged = JoseTestTokens.rsa("RS256", JoseTestKeys.rsaOther, payload: payload)
        let result = await reason(subject, forged)
        XCTAssertEqual(result, .signature)
    }

    // OpenSSL-made vector: a throwaway 2048-bit key, the signing input above, RFC 7518 3.5 PSS.
    private static let fixtureN = "rV3Ip4yXgYMuQ2RvjEqmkul5W1z53RxG5o8WsxwwScMIJhOH5JUxnhxgta5E-VZQzRKjn-Z01U-7aTzQQvoE_jThTaGAlZi5hM6M2SRsEaKQNWaHPig_E1F3yM_1oaEod1eAtVW5KQC4JOjdsB_RByobezmfzRyzpyEZikxNhcNSGcr7an-VhKniaPsS6jlTWBZhpvcT3p1oNPbEOLS1mxAkv2DL2shbE7n4mNJK36q3fUQYi9k14Ze521nRgQHmzkM9gL5YzyWBQAVCkpnGFBNM7tdAxsCxRVJafh870ic0GbG_UIAFr3WagLvEr4WAWnLZhQiyO-YBEjF46TBjhQ"
    private static let fixtureSignatures: [(String, String)] = [
        ("PS256", "Ygp9E6_8i7ED5fSlnbOMVTtGVfkDuRo3HqY3jMzf2O_sFMwIwIC89Psa7GF0X4Y0zzV7r59C4UOEgVsGXg36jSVIErrmVMoaz0SP7Y-PoRSQt8pwP0JJvCoQDhvem5XcUv9LRcBjAOhwwhcL6QcxjpMPhllBf8wUhDhuWKHJVDcuBSYWVAhGq271hceBZJhIN6oqahKzmQd876ZpcnQ9nyB0MwLBtNZ0acPsGIxnfxvkmsed9q8kpHsMTsRUxysfkWmEe2Q52-D3ljE77QIvHC-IzMzhBP4W4gqB_ZyK8JorK2fFcoMWrnZtD2aGHcjIJ9chgA-iVYUDzSWo2FXw0Q"),
        ("RS256", "KPbeNdT7u4LjDxrG4POD-MBu3Ie5KSBjD2fKAqdaUJ5-I8FDL186mfs90m-ilOpdcPZbVB_oduT4GFLPtO8DYIXsI347f6am7F3fjd0XASCW6e89zWyv9s18c1rinveDznVJv6P1CPcndU_l7hwayyw6DGOmPVOXncHdqGuJzaxcrrPUOC8MMUq4LCKdzAlJnNf69sWSe0MsBeF9y-QABlv7A29m1a9Fbu6_SG4S503-0ZezGdRnax_CYc1VteS5cm8kvVo0oJ9hW2aDKy_Ox3fjJuc1_iQyYoobgGbJgX1vg8FBk7aIq8eN_-a3m2Jo6Hhz0R383o4GoiUfjfFuKw"),
        ("PS384", "HAWKa3CkcVztdwowahrRJUJJTOL4owATcc09c9djMR-169u4OieSirw2_JEiIxEZVzjkGiTTeM9seez_dBBAzjiRHShQJzLGYQgXMT-MTxFllW8ZFK-Tk5y2aLafkivVwq7EWX3VVlTrNBttlFr_0QWibmr2uIG_FOrhuF8Jn1kfDw9n_ukffFxJNQ18VOHu2tfDlleMXHmDS28G7r9qhF_KkN4jv4fsCiKnaFeImz_WrXtmqh54Bu9HmKz97PDF-O_B-zSA7d1aPzy5sdZFqDu8m912HovhILl67PoEzeSkJZTRFdyNX9Y9clk0jdpjzIVoWO1ltm8D8yZPQ_Dt6w"),
        ("RS384", "i1tuwWGtdaZKxz_YlGTlZu_vQ5AULgmmS2XLYL8isSnUoKLP9ii2Cq9XkLEO5tWLEkg_V6VSX1N2vNkbnE26UoaesbO18_3zpINyUACZwBRE3C9pST8n2u8JGW-GKAVqsDMhRZuhyvKw1AgIoCD2kqv9bETJfx4_mEpARG87lvvcDInRvf_ryQcPpQxmLUKM_nC9T2k2tdu4UD6LrvLVf2uilCloDQ8_inmoN-pIBdc75ylvYV_-vlZJlAagwgRThRLGi7PGkzKW5jOhSlDu8joaQyY13gDRz7V-wKb_35oCJJaBYeiQynVNFxmKSdsPrOCkYCQ5In_23TXRXMtFEA"),
        ("PS512", "DcuNNklhOzjTqs11J0r71ms42aN8y2SQz-JaGKsDZeDlmfK5XPphBY5jACJAR2CrAPaxPCCvZQJhVdoHVBXL9lOTynMPDibgELU5O87agIJY7EbBmZMDqwMUppTyCm5ReidVID-u5mxWauwguV-c_qGEeW2smMDRjejEx6c1S_SIrUvrxKL0sJcmaHey-_vx9ajCtSDAOkh-ZNkjibiU6D-rWtSAkIY3vseJ3SW4tBpCT7RKJhaWL-SOYdoZGGCtgKW1NyZpRZnAqlxbgyRpDkNCnl_vEwCntLswy6h3VXH0axRqeWy8SpY0uPqKdNW1hEH8_uudhswPIV7gfmZMDw"),
        ("RS512", "bDmUCqtBm3X-eE-zXLMyeu8QOB_OIulUSwuCR53xo7MFJ87TudzfncEnH17ze4yfxYu-6_XMlFI0vX6Zfn1UHVZ-hGbFg9YY9JRHExjhkVLkoNxvajqDfixIb8QLrOP6u36Fngdv8P3A6HaQViSC7lDOAoJGTHTB8WZdwkjErsvxTXQVvtXnvNa3HlwkZIf7rjX25bByUuaVgFDzBvpQadiSaK8jnnBMis8l56AURg2YWPXvxmbAmSajed7OHM-GuJzlsnnnkZxPNLU8A2IbFNRatZkHM6rwQCkUViJ27Swn42xWt94228mjj6GKlSMNpYGda_i7hPJv0qyb_bRVdw"),
    ]
}
