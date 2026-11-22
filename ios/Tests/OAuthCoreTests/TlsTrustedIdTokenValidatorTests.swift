import CryptoKit
import Foundation
import XCTest
@testable import OAuthCore

/// `TlsTrustedIdTokenValidator`: every claim check of `JwksIdTokenValidator`, no signature check
/// (`spec/versola-sdk-api.md` section 9). The tokens carry a signature that is garbage on purpose;
/// the claim cases mirror `IdTokenValidatorTests` so that the two validators cannot drift apart
/// unnoticed, and the Android `TlsTrustedIdTokenValidatorTest` is the behavioural twin.
final class TlsTrustedIdTokenValidatorTests: XCTestCase {
    private let issuer = "https://issuer.example.com"
    private let clientId = "client-1"
    private let now = Date(timeIntervalSince1970: 1_900_000_000)
    private let accessToken = "access-token-example"

    private func validator(tolerance: TimeInterval = 60, issuer: String? = nil) -> TlsTrustedIdTokenValidator {
        let at = now
        return TlsTrustedIdTokenValidator(issuer: issuer ?? self.issuer, clientId: clientId, clockSkewTolerance: tolerance, clock: Clock(now: { at }))
    }

    private func secs(_ offset: Double) -> Int { Int(now.timeIntervalSince1970 + offset) }

    private func claims(_ overrides: [String: Any?] = [:]) -> String {
        var members: [String: Any?] = [
            "iss": issuer, "sub": "user-1", "aud": clientId, "exp": secs(3600), "iat": secs(-10), "nonce": "nonce-1",
        ]
        for (key, value) in overrides { members[key] = value }
        return JoseTestTokens.json(members)
    }

    /// A token whose signature is not one: the validator under test must not look at it.
    private func token(_ overrides: [String: Any?] = [:], alg: String = "ES256") -> String {
        let header = JoseBase64Url.encode(Data(#"{"alg":"\#(alg)","typ":"JWT"}"#.utf8))
        let payload = JoseBase64Url.encode(Data(claims(overrides).utf8))
        return header + "." + payload + "." + JoseBase64Url.encode(Data("not a signature".utf8))
    }

    private func validate(
        _ token: String, nonce: String? = "nonce-1", access: String? = nil, maxAge: Int? = nil,
        previous: IdTokenClaims? = nil, using validator: TlsTrustedIdTokenValidator? = nil
    ) async throws -> IdTokenClaims {
        try await (validator ?? self.validator()).validate(idToken: token, expectedNonce: nonce, accessToken: access, maxAge: maxAge, previous: previous, serverTime: nil)
    }

    private func rejection(
        _ token: String, nonce: String? = "nonce-1", access: String? = nil, maxAge: Int? = nil,
        previous: IdTokenClaims? = nil, using validator: TlsTrustedIdTokenValidator? = nil,
        file: StaticString = #filePath, line: UInt = #line
    ) async -> IdTokenRejection? {
        let error = await joseThrown(file: file, line: line) {
            _ = try await validate(token, nonce: nonce, access: access, maxAge: maxAge, previous: previous, using: validator)
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

    // MARK: the point: no signature check

    func testWellFormedTokenWithAGarbageSignatureValidatesBecauseTlsStandsInForTheSignature() async throws {
        let validated = try await validate(token(["auth_time": secs(-100), "acr": "urn:acr:2"]))
        XCTAssertEqual(validated.subject, "user-1")
        XCTAssertEqual(validated.issuer, issuer)
        XCTAssertEqual(validated.audience, [clientId])
        XCTAssertEqual(validated.authTime, now.addingTimeInterval(-100))
        XCTAssertEqual(validated.acr, "urn:acr:2")
        XCTAssertNil(validated.authorizedParty)
    }

    func testTokenWithAnEmptySignatureValidatesToo() async throws {
        let unsigned = JoseBase64Url.encode(Data(#"{"alg":"ES256"}"#.utf8)) + "." + JoseBase64Url.encode(Data(claims().utf8)) + "."
        let validated = try await validate(unsigned)
        XCTAssertEqual(validated.subject, "user-1")
    }

    // MARK: algorithm

    func testAlgNoneInAnyCaseIsRefusedAsAlgorithm() async {
        for alg in ["none", "None", "NONE", "nOnE"] {
            let reason = await rejection(token(alg: alg))
            XCTAssertEqual(reason, .algorithm, alg)
        }
    }

    func testAlgNoneWithAnEmptySignatureIsRefusedAsAlgorithmAndNotAsAMalformedToken() async {
        let unsigned = JoseTestTokens.jws(header: #"{"alg":"none"}"#, payload: claims(), sign: nil)
        let reason = await rejection(unsigned)
        XCTAssertEqual(reason, .algorithm)
    }

    // MARK: iss, aud, azp

    func testDifferentIssIsRefusedAsIssuer() async {
        let reason = await rejection(token(["iss": "https://evil.example.com"]))
        XCTAssertEqual(reason, .issuer)
    }

    func testIssDifferingOnlyByATrailingSlashIsRefusedAsIssuer() async {
        let reason = await rejection(token(["iss": issuer + "/"]))
        XCTAssertEqual(reason, .issuer)
    }

    func testMissingIssIsRefusedAsIssuer() async {
        let reason = await rejection(token(["iss": nil]))
        XCTAssertEqual(reason, .issuer)
    }

    func testIssuerIsTheOneTheValidatorWasBuiltWithIncludingATrailingSlash() async throws {
        let slashed = validator(issuer: issuer + "/")
        let accepted = try await validate(token(["iss": issuer + "/"]), using: slashed)
        XCTAssertEqual(accepted.issuer, issuer + "/")
        let refused = await rejection(token(["iss": issuer]), using: slashed)
        XCTAssertEqual(refused, .issuer)
    }

    func testAudWithoutTheClientIdIsRefusedAsAudience() async {
        let reason = await rejection(token(["aud": "other-client"]))
        XCTAssertEqual(reason, .audience)
    }

    func testMissingAudIsRefusedAsAudience() async {
        let reason = await rejection(token(["aud": nil]))
        XCTAssertEqual(reason, .audience)
    }

    func testSeveralAudiencesWithoutAzpAreRefusedAsAudience() async {
        let reason = await rejection(token(["aud": [clientId, "other"]]))
        XCTAssertEqual(reason, .audience)
    }

    func testAzpThatIsNotTheClientIdIsRefusedAsAudience() async {
        let reason = await rejection(token(["aud": [clientId, "other"], "azp": "other"]))
        XCTAssertEqual(reason, .audience)
    }

    func testSeveralAudiencesWithAzpEqualToTheClientIdValidate() async throws {
        let validated = try await validate(token(["aud": [clientId, "other"], "azp": clientId]))
        XCTAssertEqual(validated.authorizedParty, clientId)
    }

    // MARK: times

    func testExpBeyondTheToleranceInThePastIsRefusedAsExpired() async {
        let reason = await rejection(token(["exp": secs(-61)]))
        XCTAssertEqual(reason, .expired)
    }

    func testExpInsideTheToleranceStillValidates() async throws {
        _ = try await validate(token(["exp": secs(-30)]))
    }

    func testMissingIatIsRefusedAsIssuedAt() async {
        let reason = await rejection(token(["iat": nil]))
        XCTAssertEqual(reason, .issuedAt)
    }

    func testIatInTheFutureBeyondTheToleranceIsRefusedAsIssuedAt() async {
        let reason = await rejection(token(["iat": secs(61)]))
        XCTAssertEqual(reason, .issuedAt)
    }

    func testIatInTheFutureInsideTheToleranceValidates() async throws {
        _ = try await validate(token(["iat": secs(30)]))
    }

    func testNbfInTheFutureBeyondTheToleranceIsRefusedAsIssuedAt() async {
        let reason = await rejection(token(["nbf": secs(61)]))
        XCTAssertEqual(reason, .issuedAt)
    }

    // MARK: nonce, auth_time

    func testNonceThatDiffersFromTheRequestsIsRefusedAsNonce() async {
        let reason = await rejection(token(["nonce": "other"]))
        XCTAssertEqual(reason, .nonce)
    }

    func testMissingNonceWhenOneWasSentIsRefusedAsNonce() async {
        let reason = await rejection(token(["nonce": nil]))
        XCTAssertEqual(reason, .nonce)
    }

    func testNoNonceIsRequiredOnARefresh() async throws {
        _ = try await validate(token(["nonce": nil]), nonce: nil, previous: previous())
    }

    func testAuthTimeOlderThanMaxAgeIsRefusedAsAuthTime() async {
        let reason = await rejection(token(["auth_time": secs(-500)]), maxAge: 100)
        XCTAssertEqual(reason, .authTime)
    }

    func testMissingAuthTimeUnderMaxAgeIsRefusedAsAuthTime() async {
        let reason = await rejection(token(), maxAge: 100)
        XCTAssertEqual(reason, .authTime)
    }

    func testAuthTimeWithinMaxAgeValidatesAndNoneIsRequiredWithoutMaxAge() async throws {
        _ = try await validate(token(["auth_time": secs(-50)]), maxAge: 100)
        _ = try await validate(token())
    }

    func testRefreshWhoseAuthTimeMovedBackwardsIsRefusedAsAuthTime() async {
        let reason = await rejection(token(["auth_time": secs(-500)]), nonce: nil, previous: previous(authTime: now.addingTimeInterval(-100)))
        XCTAssertEqual(reason, .authTime)
    }

    // MARK: at_hash

    func testAtHashThatIsTheLeftHalfOfTheDigestOfTheAccessTokenValidates() async throws {
        let hash = atHash(Array(SHA256.hash(data: Data(accessToken.utf8))))
        _ = try await validate(token(["at_hash": hash]), access: accessToken)
    }

    func testAtHashOfAnotherAccessTokenIsRefusedAsAccessTokenHash() async {
        let hash = atHash(Array(SHA256.hash(data: Data("another".utf8))))
        let reason = await rejection(token(["at_hash": hash]), access: accessToken)
        XCTAssertEqual(reason, .accessTokenHash)
    }

    func testAtHashComputedWithTheWrongDigestForTheAlgorithmIsRefusedAsAccessTokenHash() async {
        let hash = atHash(Array(SHA384.hash(data: Data(accessToken.utf8))))
        let reason = await rejection(token(["at_hash": hash]), access: accessToken)
        XCTAssertEqual(reason, .accessTokenHash)
    }

    func testAtHashUnderAnAlgorithmThatNamesNoDigestIsRefusedAsAlgorithmAndNotPassed() async {
        // Nothing verified the algorithm here, so a name outside the closed set can reach the at_hash
        // check; a claim that cannot be checked is a refusal, not a pass.
        let reason = await rejection(token(["at_hash": "anything"], alg: "HS256"), access: accessToken)
        XCTAssertEqual(reason, .algorithm)
    }

    func testAtHashIsNotCheckedWhenNoAccessTokenWasIssued() async throws {
        _ = try await validate(token(["at_hash": "anything"]), access: nil)
    }

    // MARK: sub on refresh, shape

    func testRefreshWhoseSubChangedIsRefusedAsMalformed() async {
        let reason = await rejection(token(), nonce: nil, previous: previous(subject: "user-2"))
        XCTAssertEqual(reason, .malformed)
    }

    func testRefreshWithTheSameSubValidates() async throws {
        _ = try await validate(token(), nonce: nil, previous: previous())
    }

    func testStringThatIsNotThreeSegmentsIsRefusedAsMalformed() async {
        for text in ["not-a-jwt", "a.b", "a.b.c.d", ""] {
            let reason = await rejection(text)
            XCTAssertEqual(reason, .malformed, text)
        }
    }

    func testMissingSubOrExpIsRefusedAsMalformed() async {
        let noSub = await rejection(token(["sub": nil]))
        let noExp = await rejection(token(["exp": nil]))
        XCTAssertEqual(noSub, .malformed)
        XCTAssertEqual(noExp, .malformed)
    }

    func testClaimChecksRunOnATokenTheKeySetValidatorWouldHaveRefusedForItsSignature() async {
        // Wrong issuer AND a bad signature: here the issuer is the first refusal, there is no signature to fail.
        let reason = await rejection(token(["iss": "https://evil.example.com"]))
        XCTAssertEqual(reason, .issuer)
    }
}
