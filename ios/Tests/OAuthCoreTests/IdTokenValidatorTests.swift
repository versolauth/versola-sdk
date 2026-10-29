import CryptoKit
import Foundation
import XCTest
@testable import OAuthCore

// Scenarios 25 to 27 at the unit tier: the reason each check refuses with, and the order the
// refusals come in. Stubs only; the wiring against a real provider is the conformance tier.
final class IdTokenValidatorTests: XCTestCase {
    private let issuer = "https://issuer.example.com"
    private let clientId = "client-1"
    private let now = Date(timeIntervalSince1970: 1_900_000_000)
    private let accessToken = "access-token-example"
    private let jwksUri = "https://issuer.example.com/jwks.json"

    private var jwksBody: Data {
        JoseTestTokens.jwks(
            JoseTestKeys.rsa.jwk(kid: "rsa"), JoseTestKeys.p256.jwk(kid: "p256"),
            JoseTestKeys.p384.jwk(kid: "p384"), JoseTestKeys.p521.jwk(kid: "p521")
        )
    }

    private func stubWithKeys() async -> JoseStubHTTP {
        let stub = JoseStubHTTP()
        await stub.enqueue("/jwks.json", body: jwksBody)
        return stub
    }

    private func validator(
        _ stub: JoseStubHTTP, allowed: [String] = [], uri: String? = nil, tolerance: TimeInterval = 60,
        jwks: JwksClient? = nil, clock: Date? = nil
    ) -> JwksIdTokenValidator {
        let at = clock ?? now
        let resolvedUri = uri ?? jwksUri
        return JwksIdTokenValidator(
            issuer: { [issuer] in issuer }, clientId: clientId,
            jwksUri: { uri == "" ? nil : resolvedUri }, allowedAlgorithms: { allowed },
            jwks: jwks ?? JwksClient(httpClient: stub), clockSkewTolerance: tolerance, clock: Clock(now: { at })
        )
    }

    private func secs(_ offset: Double) -> Int { Int(now.timeIntervalSince1970 + offset) }

    private func claims(_ overrides: [String: Any?] = [:]) -> String {
        var members: [String: Any?] = [
            "iss": issuer, "sub": "user-1", "aud": clientId, "exp": secs(3600), "iat": secs(-10), "nonce": "nonce-1",
        ]
        for (key, value) in overrides { members[key] = value }
        return JoseTestTokens.json(members)
    }

    private func rsToken(_ overrides: [String: Any?] = [:]) -> String {
        JoseTestTokens.rsa("RS256", payload: claims(overrides), kid: "rsa")
    }

    private func validate(
        _ token: String, _ validator: JwksIdTokenValidator, nonce: String? = "nonce-1", access: String? = nil,
        maxAge: Int? = nil, previous: IdTokenClaims? = nil, serverTime: Date? = nil
    ) async throws -> IdTokenClaims {
        try await validator.validate(idToken: token, expectedNonce: nonce, accessToken: access, maxAge: maxAge, previous: previous, serverTime: serverTime)
    }

    private func ok(_ overrides: [String: Any?] = [:], nonce: String? = "nonce-1", access: String? = nil, maxAge: Int? = nil, previous: IdTokenClaims? = nil, serverTime: Date? = nil, tolerance: TimeInterval = 60) async throws -> IdTokenClaims {
        let stub = await stubWithKeys()
        return try await validate(rsToken(overrides), validator(stub, tolerance: tolerance), nonce: nonce, access: access, maxAge: maxAge, previous: previous, serverTime: serverTime)
    }

    /// The reason the token is refused with, expecting `configuration(.idTokenRejected)`.
    private func rejection(
        _ overrides: [String: Any?] = [:], token: String? = nil, nonce: String? = "nonce-1", access: String? = nil,
        maxAge: Int? = nil, previous: IdTokenClaims? = nil, serverTime: Date? = nil, tolerance: TimeInterval = 60,
        allowed: [String] = [], stub: JoseStubHTTP? = nil, file: StaticString = #filePath, line: UInt = #line
    ) async -> IdTokenRejection? {
        let served: JoseStubHTTP
        if let stub { served = stub } else { served = await stubWithKeys() }
        let subject = validator(served, allowed: allowed, tolerance: tolerance)
        let built = token ?? rsToken(overrides)
        let error = await joseThrown(file: file, line: line) {
            _ = try await validate(built, subject, nonce: nonce, access: access, maxAge: maxAge, previous: previous, serverTime: serverTime)
        }
        guard case .configuration(.idTokenRejected(let reason))? = error as? OAuthError else {
            XCTFail("not idTokenRejected: \(String(describing: error))", file: file, line: line)
            return nil
        }
        return reason
    }

    private func previous(subject: String = "user-1", authTime: Date? = nil) -> IdTokenClaims {
        IdTokenClaims(subject: subject, issuer: issuer, audience: [clientId], issuedAt: now.addingTimeInterval(-1000), expiresAt: now.addingTimeInterval(1000), authTime: authTime)
    }

    private func atHash(_ digest: [UInt8]) -> String { JoseBase64Url.encode(Data(digest.prefix(digest.count / 2))) }

    // MARK: positive, one per algorithm family

    func testRs256TokenWithMatchingClaimsValidatesAndYieldsTypedClaims() async throws {
        let claims = try await ok([
            "auth_time": secs(-100), "acr": "urn:mace:incommon:iap:silver", "amr": ["pwd", "otp"],
            "email_verified": true, "custom_number": 42, "profile": ["a": [1, 2]],
        ])
        XCTAssertEqual(claims.subject, "user-1")
        XCTAssertEqual(claims.issuer, issuer)
        XCTAssertEqual(claims.audience, [clientId])
        XCTAssertEqual(claims.issuedAt, now.addingTimeInterval(-10))
        XCTAssertEqual(claims.expiresAt, now.addingTimeInterval(3600))
        XCTAssertEqual(claims.authTime, now.addingTimeInterval(-100))
        XCTAssertEqual(claims.acr, "urn:mace:incommon:iap:silver")
        XCTAssertEqual(claims.amr, ["pwd", "otp"])
        XCTAssertEqual(claims.description, "IdTokenClaims(issuer: \(issuer), subject: redacted)")
    }

    func testAdditionalHoldsTheOtherClaimsAsTextAndLeavesTheNonceAndTheTypedOnesOut() async throws {
        let claims = try await ok(["email_verified": true, "custom_number": 42, "azp": clientId, "profile": ["b": "x\"y", "a": [1, 2]], "locale": "en"])
        XCTAssertEqual(claims.additional["email_verified"], "true")
        XCTAssertEqual(claims.additional["custom_number"], "42")
        XCTAssertEqual(claims.additional["azp"], clientId)
        XCTAssertEqual(claims.additional["locale"], "en")
        XCTAssertEqual(claims.additional["profile"], #"{"a":[1,2],"b":"x\"y"}"#)
        XCTAssertNil(claims.additional["nonce"])
        for typed in ["iss", "sub", "aud", "exp", "iat"] { XCTAssertNil(claims.additional[typed], typed) }
    }

    func testPsAndRsFamiliesValidate() async throws {
        let stub = await stubWithKeys()
        let jwks = JwksClient(httpClient: stub)
        for alg in ["RS384", "RS512", "PS256", "PS384", "PS512"] {
            let token = JoseTestTokens.rsa(alg, payload: claims(), kid: "rsa")
            let result = try await validate(token, validator(stub, jwks: jwks))
            XCTAssertEqual(result.subject, "user-1", alg)
        }
    }

    func testEs256Es384AndEs512TokensValidate() async throws {
        let stub = await stubWithKeys()
        let jwks = JwksClient(httpClient: stub)
        for (key, kid) in [(JoseTestKeys.p256, "p256"), (JoseTestKeys.p384, "p384"), (JoseTestKeys.p521, "p521")] {
            let token = JoseTestTokens.ec(key, payload: claims(), kid: kid)
            let result = try await validate(token, validator(stub, jwks: jwks))
            XCTAssertEqual(result.subject, "user-1", key.alg)
        }
    }

    func testTokenWithoutKidValidatesAgainstTheOnlyKeyOfItsType() async throws {
        let stub = JoseStubHTTP()
        await stub.enqueue("/jwks.json", body: JoseTestTokens.jwks(JoseTestKeys.rsa.jwk(kid: "only-rsa"), JoseTestKeys.p256.jwk(kid: "an-ec-key")))
        let token = JoseTestTokens.rsa("RS256", payload: claims(), kid: nil)
        let result = try await validate(token, validator(stub))
        XCTAssertEqual(result.subject, "user-1")
    }

    func testAlgorithmTheProviderAdvertisesIsAccepted() async throws {
        let stub = await stubWithKeys()
        let result = try await validate(rsToken(), validator(stub, allowed: ["ES256", "RS256"]))
        XCTAssertEqual(result.subject, "user-1")
    }

    // MARK: algorithm

    func testAlgNoneIsRefusedAsAlgorithmWithoutANetworkRequest() async {
        let stub = JoseStubHTTP()
        let token = JoseTestTokens.jws(header: #"{"alg":"none","kid":"rsa"}"#, payload: claims(), sign: nil)
        let reason = await rejection(token: token, stub: stub)
        let count = await stub.requestCount()
        XCTAssertEqual(reason, .algorithm)
        XCTAssertEqual(count, 0)
    }

    func testHs256KeyConfusionTokenIsRefusedAsAlgorithmWithoutANetworkRequest() async {
        let stub = JoseStubHTTP()
        // An HMAC keyed with the provider's public modulus, the classic downgrade.
        let key = SymmetricKey(data: JoseTestKeys.rsa.n)
        let token = JoseTestTokens.jws(header: #"{"alg":"HS256","typ":"JWT","kid":"rsa"}"#, payload: claims(), sign: { Data(HMAC<SHA256>.authenticationCode(for: $0, using: key)) })
        let reason = await rejection(token: token, stub: stub)
        let count = await stub.requestCount()
        XCTAssertEqual(reason, .algorithm)
        XCTAssertEqual(count, 0)
    }

    func testAlgorithmOutsideTheClosedSetIsRefusedAsAlgorithm() async {
        for alg in ["HS384", "HS512", "ES256K", "EdDSA", "none", "rs256"] {
            let stub = JoseStubHTTP()
            let token = JoseTestTokens.jws(header: "{\"alg\":\"\(alg)\"}", payload: claims(), sign: nil)
            let reason = await rejection(token: token, stub: stub)
            let count = await stub.requestCount()
            XCTAssertEqual(reason, .algorithm, alg)
            XCTAssertEqual(count, 0, alg)
        }
    }

    func testAlgorithmTheProviderDoesNotAdvertiseIsRefusedAsAlgorithmWithoutANetworkRequest() async {
        let stub = JoseStubHTTP()
        let reason = await rejection(allowed: ["ES256"], stub: stub)
        let count = await stub.requestCount()
        XCTAssertEqual(reason, .algorithm)
        XCTAssertEqual(count, 0)
    }

    // MARK: signature and key selection

    func testSignatureMadeByAnotherKeyUnderTheSameKidIsRefusedAsSignature() async {
        let token = JoseTestTokens.rsa("RS256", JoseTestKeys.rsaOther, payload: claims(), kid: "rsa")
        let reason = await rejection(token: token)
        XCTAssertEqual(reason, .signature)
    }

    func testPayloadAlteredAfterSigningIsRefusedAsSignature() async {
        let parts = rsToken().split(separator: ".").map(String.init)
        let forged = parts[0] + "." + JoseBase64Url.encode(Data(claims(["sub": "admin"]).utf8)) + "." + parts[2]
        let reason = await rejection(token: forged)
        XCTAssertEqual(reason, .signature)
    }

    func testFlippedSignatureByteIsRefusedAsSignature() async {
        var parts = rsToken().split(separator: ".").map(String.init)
        var signature = JoseBase64Url.decode(parts[2])!
        signature[0] ^= 0x01
        parts[2] = JoseBase64Url.encode(signature)
        let reason = await rejection(token: parts.joined(separator: "."))
        XCTAssertEqual(reason, .signature)
    }

    func testKidNamingAKeyOfAnotherTypeIsRefusedAsSignature() async {
        let token = JoseTestTokens.ec(JoseTestKeys.p256, payload: claims(), kid: "rsa")
        let reason = await rejection(token: token)
        XCTAssertEqual(reason, .signature)
    }

    func testUnknownKidRefetchesTheKeySetExactlyOnceAndARotatedInKeyThenValidates() async throws {
        let stub = JoseStubHTTP()
        let jwks = JwksClient(httpClient: stub)
        await stub.enqueue("/jwks.json", body: JoseTestTokens.jwks(JoseTestKeys.rsa.jwk(kid: "rsa")))
        _ = try await validate(rsToken(), validator(stub, jwks: jwks))
        var count = await stub.requestCount()
        XCTAssertEqual(count, 1)

        await stub.enqueue("/jwks.json", body: JoseTestTokens.jwks(JoseTestKeys.rsa.jwk(kid: "rsa"), JoseTestKeys.rsaOther.jwk(kid: "rotated")))
        let token = JoseTestTokens.rsa("RS256", JoseTestKeys.rsaOther, payload: claims(), kid: "rotated")
        let result = try await validate(token, validator(stub, jwks: jwks))

        XCTAssertEqual(result.subject, "user-1")
        count = await stub.requestCount()
        XCTAssertEqual(count, 2)
    }

    func testSecondUnknownKidAfterTheRefetchIsSignatureAndNoThirdRequestIsMade() async throws {
        // Scenario 26, case B: exactly one refetch before the rejection.
        let stub = JoseStubHTTP()
        let jwks = JwksClient(httpClient: stub)
        await stub.enqueue("/jwks.json", body: JoseTestTokens.jwks(JoseTestKeys.rsa.jwk(kid: "rsa")))
        _ = try await validate(rsToken(), validator(stub, jwks: jwks))
        await stub.enqueue("/jwks.json", body: JoseTestTokens.jwks(JoseTestKeys.rsa.jwk(kid: "rsa")))
        // A third answer is queued so that a loop would show up as a request, not a hang.
        await stub.enqueue("/jwks.json", body: JoseTestTokens.jwks(JoseTestKeys.rsa.jwk(kid: "rsa")))
        let token = JoseTestTokens.rsa("RS256", JoseTestKeys.rsaOther, payload: claims(), kid: "unknown")

        let error = await joseThrown { _ = try await validate(token, validator(stub, jwks: jwks)) }
        XCTAssertEqual((error as? OAuthError), .configuration(.idTokenRejected(.signature)))
        let count = await stub.requestCount()
        XCTAssertEqual(count, 2)
    }

    func testUnknownKidOnAColdCacheCostsOneRequestNotTwo() async {
        let stub = JoseStubHTTP()
        await stub.enqueue("/jwks.json", body: JoseTestTokens.jwks(JoseTestKeys.rsa.jwk(kid: "rsa")))
        await stub.enqueue("/jwks.json", body: JoseTestTokens.jwks(JoseTestKeys.rsa.jwk(kid: "rsa")))
        let token = JoseTestTokens.rsa("RS256", JoseTestKeys.rsaOther, payload: claims(), kid: "unknown")
        let reason = await rejection(token: token, stub: stub)
        let count = await stub.requestCount()
        XCTAssertEqual(reason, .signature)
        XCTAssertEqual(count, 1)
    }

    func testTokenWithoutKidIsRefusedWhenSeveralKeysOfItsTypeCouldHaveSignedIt() async {
        let stub = JoseStubHTTP()
        await stub.enqueue("/jwks.json", body: JoseTestTokens.jwks(JoseTestKeys.rsa.jwk(kid: "a"), JoseTestKeys.rsaOther.jwk(kid: "b")))
        let token = JoseTestTokens.rsa("RS256", payload: claims(), kid: nil)
        let reason = await rejection(token: token, stub: stub)
        XCTAssertEqual(reason, .signature)
    }

    func testKeyMarkedForEncryptionOrPinnedToAnotherAlgorithmIsNotUsed() async throws {
        let encryption = JoseStubHTTP()
        await encryption.enqueue("/jwks.json", body: JoseTestTokens.jwks(JoseTestKeys.rsa.jwk(kid: "rsa", use: "enc")))
        let encReason = await rejection(stub: encryption)
        XCTAssertEqual(encReason, .signature)

        let pinned = JoseStubHTTP()
        await pinned.enqueue("/jwks.json", body: JoseTestTokens.jwks(JoseTestKeys.rsa.jwk(kid: "rsa", alg: "RS512")))
        let pinnedReason = await rejection(stub: pinned)
        XCTAssertEqual(pinnedReason, .signature)

        let matching = JoseStubHTTP()
        await matching.enqueue("/jwks.json", body: JoseTestTokens.jwks(JoseTestKeys.rsa.jwk(kid: "rsa", alg: "RS256", use: "sig")))
        // The same key, pinned to the algorithm in use and marked for signing, is the positive case.
        let result = try await validate(rsToken(), validator(matching))
        XCTAssertEqual(result.subject, "user-1")
    }

    func testProviderWithoutAJwksUriIsProviderUnsupportedAndNothingIsFetched() async {
        let stub = JoseStubHTTP()
        let error = await joseThrown { _ = try await validate(rsToken(), validator(stub, uri: "")) }
        let count = await stub.requestCount()
        XCTAssertEqual(error as? OAuthError, .configuration(.providerUnsupported(capability: "jwks_uri")))
        XCTAssertEqual(count, 0)
    }

    func testUnreachableJwksUriIsANetworkFailureAndNotARejection() async {
        let stub = JoseStubHTTP()
        await stub.enqueueFailure("/jwks.json")
        let error = await joseThrown { _ = try await validate(rsToken(), validator(stub)) }
        guard case .recoverable(.network)? = error as? OAuthError else { return XCTFail("\(String(describing: error))") }
    }

    func testClaimsAreNotReadBeforeTheSignatureIsVerified() async {
        // Wrong issuer AND a bad signature: the signature is the first refusal.
        let token = JoseTestTokens.rsa("RS256", JoseTestKeys.rsaOther, payload: claims(["iss": "https://evil.example.com"]), kid: "rsa")
        let reason = await rejection(token: token)
        XCTAssertEqual(reason, .signature)
    }

    // MARK: iss, aud

    func testDifferentIssIsRefusedAsIssuer() async {
        let reason = await rejection(["iss": "https://evil.example.com"])
        XCTAssertEqual(reason, .issuer)
    }

    func testIssDifferingOnlyByATrailingSlashIsRefusedAsIssuer() async {
        let reason = await rejection(["iss": issuer + "/"])
        XCTAssertEqual(reason, .issuer)
    }

    func testMissingIssIsRefusedAsIssuer() async {
        let reason = await rejection(["iss": nil])
        XCTAssertEqual(reason, .issuer)
    }

    func testAudWithoutTheClientIdIsRefusedAsAudience() async {
        let reason = await rejection(["aud": "another-client"])
        XCTAssertEqual(reason, .audience)
    }

    func testMissingAudIsRefusedAsAudience() async {
        let reason = await rejection(["aud": nil])
        XCTAssertEqual(reason, .audience)
    }

    func testSeveralAudiencesWithoutAzpAreRefusedAsAudience() async {
        let reason = await rejection(["aud": [clientId, "other"]])
        XCTAssertEqual(reason, .audience)
    }

    func testSeveralAudiencesWithAnAzpThatIsNotTheClientIdAreRefusedAsAudience() async {
        let reason = await rejection(["aud": [clientId, "other"], "azp": "other"])
        XCTAssertEqual(reason, .audience)
    }

    func testSeveralAudiencesWithAzpEqualToTheClientIdValidate() async throws {
        let claims = try await ok(["aud": ["other", clientId], "azp": clientId])
        XCTAssertEqual(claims.audience, ["other", clientId])
    }

    func testSingleAudienceInAnArrayValidatesWithoutAzp() async throws {
        let claims = try await ok(["aud": [clientId]])
        XCTAssertEqual(claims.audience, [clientId])
    }

    func testAzpThatIsNotTheClientIdIsRefusedAsAudienceEvenWithOneAudience() async {
        let reason = await rejection(["azp": "other"])
        XCTAssertEqual(reason, .audience)
    }

    // MARK: exp, iat

    func testExpBeyondTheToleranceInThePastIsRefusedAsExpired() async {
        let reason = await rejection(["exp": secs(-61)])
        XCTAssertEqual(reason, .expired)
    }

    func testExpExactlyAtNowMinusTheToleranceIsRefusedAsExpired() async {
        let reason = await rejection(["exp": secs(-60)])
        XCTAssertEqual(reason, .expired)
    }

    func testExpInsideTheToleranceStillValidates() async throws {
        let claims = try await ok(["exp": secs(-59)])
        XCTAssertEqual(claims.subject, "user-1")
    }

    func testMissingIatIsRefusedAsIssuedAt() async {
        let reason = await rejection(["iat": nil])
        XCTAssertEqual(reason, .issuedAt)
    }

    func testIatInTheFutureBeyondTheToleranceIsRefusedAsIssuedAt() async {
        let reason = await rejection(["iat": secs(61)])
        XCTAssertEqual(reason, .issuedAt)
    }

    func testIatInTheFutureInsideTheToleranceValidates() async throws {
        let claims = try await ok(["iat": secs(60)])
        XCTAssertEqual(claims.subject, "user-1")
    }

    func testZeroToleranceMakesTheClockExact() async {
        let late = await rejection(["iat": secs(1)], tolerance: 0)
        let expired = await rejection(["exp": secs(0)], tolerance: 0)
        XCTAssertEqual(late, .issuedAt)
        XCTAssertEqual(expired, .expired)
    }

    func testServerTimeIsUsedInsteadOfTheDeviceClock() async throws {
        // The device clock is two hours behind the provider's: every iat looks like the future.
        let stub = await stubWithKeys()
        let behind = now.addingTimeInterval(-7200)
        let token = rsToken()
        let withoutServerTime = await joseThrown { _ = try await validate(token, validator(stub, clock: behind)) }
        XCTAssertEqual(withoutServerTime as? OAuthError, .configuration(.idTokenRejected(.issuedAt)))

        let stub2 = await stubWithKeys()
        let result = try await validate(token, validator(stub2, clock: behind), serverTime: now)
        XCTAssertEqual(result.subject, "user-1")
    }

    func testServerTimeIsNotRescuedByTheToleranceWhenTheTokenIsReallyExpired() async {
        // Scenario 27, case D: expired relative to the server's Date, whatever the device clock says.
        let ahead = now.addingTimeInterval(-7200)
        let stub = await stubWithKeys()
        let error = await joseThrown { _ = try await validate(rsToken(["exp": secs(-61)]), validator(stub, clock: ahead), serverTime: now) }
        XCTAssertEqual(error as? OAuthError, .configuration(.idTokenRejected(.expired)))
    }

    // MARK: nonce

    func testNonceThatDiffersFromTheRequestsIsRefusedAsNonce() async {
        let reason = await rejection(["nonce": "nonce-2"])
        XCTAssertEqual(reason, .nonce)
    }

    func testNonceThatIsAPrefixOfTheRequestsIsRefusedAsNonce() async {
        let reason = await rejection(["nonce": "nonce-"])
        XCTAssertEqual(reason, .nonce)
    }

    func testMissingNonceWhenOneWasSentIsRefusedAsNonce() async {
        let reason = await rejection(["nonce": nil])
        XCTAssertEqual(reason, .nonce)
    }

    func testNoNonceIsRequiredOnARefreshAndOneThatIsPresentIsIgnored() async throws {
        let without = try await ok(["nonce": nil], nonce: nil, previous: previous())
        let with = try await ok(["nonce": "whatever"], nonce: nil, previous: previous())
        XCTAssertEqual(without.subject, "user-1")
        XCTAssertEqual(with.subject, "user-1")
    }

    // MARK: auth_time and max_age

    func testMissingAuthTimeUnderMaxAgeIsRefusedAsAuthTime() async {
        let reason = await rejection(maxAge: 300)
        XCTAssertEqual(reason, .authTime)
    }

    func testAuthTimeOlderThanMaxAgeIsRefusedAsAuthTime() async {
        let reason = await rejection(["auth_time": secs(-361)], maxAge: 300)
        XCTAssertEqual(reason, .authTime)
    }

    func testAuthTimeWithinMaxAgeValidates() async throws {
        let claims = try await ok(["auth_time": secs(-200)], maxAge: 300)
        XCTAssertEqual(claims.authTime, now.addingTimeInterval(-200))
    }

    func testMaxAgeZeroIsMetByALoginThatHappenedMomentsAgo() async throws {
        let claims = try await ok(["auth_time": secs(-2)], maxAge: 0)
        XCTAssertEqual(claims.subject, "user-1")
    }

    func testAuthTimeIsNotRequiredWithoutMaxAge() async throws {
        let claims = try await ok()
        XCTAssertNil(claims.authTime)
    }

    // MARK: refresh

    func testRefreshWhoseSubChangedIsRefusedAsMalformed() async {
        let reason = await rejection(nonce: nil, previous: previous(subject: "user-2"))
        XCTAssertEqual(reason, .malformed)
    }

    func testRefreshWhoseAuthTimeMovedBackwardsIsRefusedAsAuthTime() async {
        let reason = await rejection(["auth_time": secs(-600)], nonce: nil, previous: previous(authTime: now.addingTimeInterval(-500)))
        XCTAssertEqual(reason, .authTime)
    }

    func testRefreshWithAnUnchangedOrLaterAuthTimeValidates() async throws {
        let before = previous(authTime: now.addingTimeInterval(-500))
        let same = try await ok(["auth_time": secs(-500)], nonce: nil, previous: before)
        let later = try await ok(["auth_time": secs(-100)], nonce: nil, previous: before)
        XCTAssertEqual(same.authTime, now.addingTimeInterval(-500))
        XCTAssertEqual(later.authTime, now.addingTimeInterval(-100))
    }

    func testRefreshThatOmitsAuthTimeValidates() async throws {
        let claims = try await ok(nonce: nil, previous: previous(authTime: now.addingTimeInterval(-500)))
        XCTAssertNil(claims.authTime)
    }

    // MARK: at_hash

    func testAtHashThatIsTheLeftHalfOfSha256OfTheAccessTokenValidates() async throws {
        let hash = atHash(Array(SHA256.hash(data: Data(accessToken.utf8))))
        let claims = try await ok(["at_hash": hash], access: accessToken)
        XCTAssertEqual(claims.additional["at_hash"], hash)
    }

    func testAtHashOfAnotherAccessTokenIsRefusedAsAccessTokenHash() async {
        let hash = atHash(Array(SHA256.hash(data: Data("another-token".utf8))))
        let reason = await rejection(["at_hash": hash], access: accessToken)
        XCTAssertEqual(reason, .accessTokenHash)
    }

    func testRs256AtHashComputedWithSha384IsRefusedAsAccessTokenHash() async {
        let hash = atHash(Array(SHA384.hash(data: Data(accessToken.utf8))))
        let reason = await rejection(["at_hash": hash], access: accessToken)
        XCTAssertEqual(reason, .accessTokenHash)
    }

    func testEs384AtHashIsTheLeftHalfOfSha384AndSha256IsRefused() async throws {
        let good = atHash(Array(SHA384.hash(data: Data(accessToken.utf8))))
        let bad = atHash(Array(SHA256.hash(data: Data(accessToken.utf8))))
        let stub = await stubWithKeys()
        let jwks = JwksClient(httpClient: stub)
        let accepted = try await validate(JoseTestTokens.ec(JoseTestKeys.p384, payload: claims(["at_hash": good]), kid: "p384"), validator(stub, jwks: jwks), access: accessToken)
        XCTAssertEqual(accepted.subject, "user-1")
        let error = await joseThrown { _ = try await validate(JoseTestTokens.ec(JoseTestKeys.p384, payload: claims(["at_hash": bad]), kid: "p384"), validator(stub, jwks: jwks), access: accessToken) }
        XCTAssertEqual(error as? OAuthError, .configuration(.idTokenRejected(.accessTokenHash)))
    }

    func testAtHashIsNotCheckedWhenNoAccessTokenWasIssuedAndTokenWithoutItValidates() async throws {
        let unchecked = try await ok(["at_hash": "anything"], access: nil)
        let absent = try await ok(access: accessToken)
        XCTAssertEqual(unchecked.subject, "user-1")
        XCTAssertEqual(absent.subject, "user-1")
    }

    // MARK: malformed

    func testStringThatIsNotAJwsIsRefusedAsMalformedWithoutANetworkRequest() async {
        let stub = JoseStubHTTP()
        let reason = await rejection(token: "not-a-jwt", stub: stub)
        let count = await stub.requestCount()
        XCTAssertEqual(reason, .malformed)
        XCTAssertEqual(count, 0)
    }

    func testMissingSubIsRefusedAsMalformed() async {
        let reason = await rejection(["sub": nil])
        XCTAssertEqual(reason, .malformed)
    }

    func testMissingExpIsRefusedAsMalformed() async {
        let reason = await rejection(["exp": nil])
        XCTAssertEqual(reason, .malformed)
    }

    func testExpGivenAsAStringIsRefusedAsMalformed() async {
        let reason = await rejection(["exp": "1900000000"])
        XCTAssertEqual(reason, .malformed)
    }

    func testExpGivenAsABooleanIsRefusedAsMalformed() async {
        let reason = await rejection(["exp": true])
        XCTAssertEqual(reason, .malformed)
    }

    func testAudOfTheWrongTypeIsRefusedAsMalformed() async {
        let reason = await rejection(["aud": 5])
        XCTAssertEqual(reason, .malformed)
    }

    func testNonStringNonceIsRefusedAsMalformedEvenOnARefresh() async {
        let reason = await rejection(["nonce": 5], nonce: nil)
        XCTAssertEqual(reason, .malformed)
    }

    // MARK: stored token

    func testStoredIdTokenIsReadBackWithoutVerifyingIt() throws {
        // Signed by a key no JWKS holds: restoring a stored claim set must not need the network.
        let token = JoseTestTokens.rsa("RS256", JoseTestKeys.rsaOther, payload: claims(["auth_time": secs(-100), "amr": ["pwd"], "acr": "a", "aud": ["x", "y"], "email": "u@example.com"]))
        let stored = try IdTokenClaimsParser.parseStored(token)
        XCTAssertEqual(stored.subject, "user-1")
        XCTAssertEqual(stored.issuer, issuer)
        XCTAssertEqual(stored.audience, ["x", "y"])
        XCTAssertEqual(stored.authTime, now.addingTimeInterval(-100))
        XCTAssertEqual(stored.amr, ["pwd"])
        XCTAssertEqual(stored.acr, "a")
        XCTAssertEqual(stored.additional["email"], "u@example.com")
        XCTAssertNil(stored.additional["nonce"])
    }

    func testStoredTokenThatNoLongerParsesIsRefusedAsMalformed() {
        for text in ["", "a.b", "a.b.c", JoseTestTokens.jws(header: #"{"alg":"RS256"}"#, payload: #"{"iss":"x"}"#, sign: nil)] {
            XCTAssertThrowsError(try IdTokenClaimsParser.parseStored(text), text) { error in
                XCTAssertEqual((error as? JwsRejection)?.reason, .malformed)
            }
        }
    }
}
