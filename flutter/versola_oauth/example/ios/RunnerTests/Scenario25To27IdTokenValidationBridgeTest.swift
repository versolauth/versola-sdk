import Foundation
@testable import OAuthCore
import XCTest
@testable import OAuthClient
@testable import versola_oauth

/// `25-id-token-nonce-mismatch`, `26-id-token-signature-invalid` and `27-id-token-claims-rejected`
/// through the bridge: the proxy re-signs the provider's ID token with the harness's key, served
/// from a substituted JWKS, so that only the claim under test is wrong. The SDK must refuse with
/// the matching reason, persist nothing and settle on the state it had; here the refusal is what
/// the plugin puts on the wire, a `configuration` error whose case is `idTokenRejected` and whose
/// `idTokenRejection` is the reason in the spelling Dart's `IdTokenRejection` enum reads. The
/// native driver's tests are the source (`Scenario25To27IdTokenValidationTest`), case for case.
final class Scenario25To27IdTokenValidationBridgeTest: BridgeConformance {
    private let signer = HarnessSigner()

    /// Installs the harness JWKS and an ID-token rewrite; returns the metadata the paths came from.
    private func fault(
        _ bridge: Bridge, alg: String = "RS256", mutate: @escaping @Sendable ([String: Any]) -> [String: Any]
    ) async throws -> ProviderMetadata {
        let metadata = try await bridge.native.metadata()
        let signer = self.signer
        network.rewrite(path(metadata.jwksUri)) { _ in signer.jwks() }
        network.rewriteJSON(path(metadata.tokenEndpoint)) { response in
            guard let idToken = response["id_token"] as? String else { return response }
            return HarnessSigner.withIdToken(response, signer.resign(idToken, alg: alg, mutate: mutate))
        }
        return metadata
    }

    /// The reason of the rejection, as the wire spells it: the case name with its first letter lowered.
    private func rejected(_ bridge: Bridge, _ options: LoginOptionsMessage = DartSide.loginOptions(), file: StaticString = #filePath, line: UInt = #line) async throws -> String? {
        let result = try await bridge.dart.login(options)
        let error = try failure(result)
        assertError(error, .configuration, "idTokenRejected", file: file, line: line)
        return error.idTokenRejection
    }

    /// `since`: the transcript's size when the fault was installed; what came before is not the rejection's.
    private func assertNothingPersisted(_ bridge: Bridge, _ metadata: ProviderMetadata, since: Int = 0, file: StaticString = #filePath, line: UInt = #line) async throws {
        let state = try await bridge.dart.sessionState()
        XCTAssertEqual(state, .unauthenticated, file: file, line: line)
        let claims = try await bridge.dart.claims()
        XCTAssertNil(claims, file: file, line: line)
        // No userinfo, no protected origin, no revocation after the rejection.
        let after = Array(network.transcript.dropFirst(since))
        let userinfo = try XCTUnwrap(metadata.userinfoEndpoint, file: file, line: line)
        XCTAssertFalse(after.contains { $0.method == "GET" && $0.url.hasPrefix(userinfo) }, file: file, line: line)
        XCTAssertFalse(after.contains { $0.url.hasPrefix(ResourceServer.origin) }, file: file, line: line)
        if let revocation = metadata.revocationEndpoint {
            XCTAssertFalse(after.contains { $0.method == "POST" && $0.url.hasPrefix(revocation) }, file: file, line: line)
        }
        // The store is as it was before login(): nothing to refresh with.
        let token = try await bridge.dart.accessToken()
        XCTAssertEqual(try failure(token).category, .reauthenticate, file: file, line: line)
    }

    // MARK: - 25

    func test25NonceMismatchIsRejectedBeforeAnythingIsPersisted() async throws {
        let bridge = try await bridge()
        let metadata = try await fault(bridge) { with($0, "nonce", "not-the-nonce-the-sdk-sent") }

        let reason = try await rejected(bridge)

        XCTAssertEqual(reason, "nonce")
        try await assertNothingPersisted(bridge, metadata)
    }

    func test25RejectedLoginOverAStoredGrantLeavesTheSessionAuthenticatedAsItWas() async throws {
        let bridge = try await bridge()
        try ok(await bridge.dart.login())
        let claimsBefore = try await bridge.dart.claims()
        let subjectBefore = try XCTUnwrap(claimsBefore).subject
        _ = try await fault(bridge) { without($0, "nonce") }

        let reason = try await rejected(bridge)

        XCTAssertEqual(reason, "nonce")
        let state = try await bridge.dart.sessionState()
        XCTAssertEqual(state, .authenticated)
        let claimsAfter = try await bridge.dart.claims()
        XCTAssertEqual(claimsAfter?.subject, subjectBefore)
        // The stored grant still works: the access token comes without a new browser.
        _ = try token(await bridge.dart.accessToken())
        XCTAssertEqual(browser.opened.count, 2)
    }

    // MARK: - 26

    func test26ASignatureThatDoesNotVerifyIsRejectedAsSignature() async throws {
        let bridge = try await bridge()
        let metadata = try await bridge.native.metadata()
        // The provider's own keys stay; the token's signature bytes are flipped.
        network.rewriteJSON(path(metadata.tokenEndpoint)) { response in
            guard let idToken = response["id_token"] as? String else { return response }
            let parts = idToken.split(separator: ".").map(String.init)
            guard parts.count == 3, var signature = Base64Url.decode(parts[2]), !signature.isEmpty else { return response }
            signature[signature.startIndex] ^= 0x55
            return HarnessSigner.withIdToken(response, "\(parts[0]).\(parts[1]).\(Base64Url.encode(signature))")
        }

        let reason = try await rejected(bridge)

        XCTAssertEqual(reason, "signature")
        try await assertNothingPersisted(bridge, metadata)
    }

    func test26BAKeyAbsentFromJwksUriCausesExactlyOneRefetchThenSignature() async throws {
        let bridge = try await bridge()
        let metadata = try await bridge.native.metadata()
        let jwksPath = path(metadata.jwksUri)
        // Warm the key cache with a real login so the refetch is observable as such.
        try ok(await bridge.dart.login())
        _ = try await bridge.dart.logout()
        let fetchesBefore = network.matching("GET", jwksPath).count
        let since = network.transcript.count
        let other = HarnessSigner(kid: "absent-from-the-set")
        network.rewriteJSON(path(metadata.tokenEndpoint)) { response in
            guard let idToken = response["id_token"] as? String else { return response }
            return HarnessSigner.withIdToken(response, other.resign(idToken) { $0 })
        }

        let reason = try await rejected(bridge)

        XCTAssertEqual(reason, "signature")
        XCTAssertEqual(network.matching("GET", jwksPath).count - fetchesBefore, 1, "JWKS fetches during the rejected login")
        try await assertNothingPersisted(bridge, metadata, since: since)
    }

    func test26CAlgNoneWithAnEmptySignatureIsRejectedAsAlgorithmBeforeAnyKeyIsFetched() async throws {
        let bridge = try await bridge()
        let metadata = try await fault(bridge, alg: "none") { $0 }
        let jwksPath = path(metadata.jwksUri)
        let fetchesBefore = network.matching("GET", jwksPath).count

        let reason = try await rejected(bridge)

        XCTAssertEqual(reason, "algorithm")
        XCTAssertEqual(network.matching("GET", jwksPath).count, fetchesBefore)
        try await assertNothingPersisted(bridge, metadata)
    }

    func test26DHS256SignedWithTheClientIdAsKeyIsRejectedAsAlgorithm() async throws {
        let bridge = try await bridge()
        let metadata = try await fault(bridge, alg: "HS256") { $0 }

        let reason = try await rejected(bridge)

        XCTAssertEqual(reason, "algorithm")
        try await assertNothingPersisted(bridge, metadata)
    }

    // MARK: - 27

    func test27AIssDifferingByATrailingSlashIsRejectedAsIssuer() async throws {
        let bridge = try await bridge()
        let metadata = try await fault(bridge) { with($0, "iss", (($0["iss"] as? String) ?? "") + "/") }

        let reason = try await rejected(bridge)

        XCTAssertEqual(reason, "issuer")
        try await assertNothingPersisted(bridge, metadata)
    }

    func test27BAudEqualToAnotherClientIdIsRejectedAsAudience() async throws {
        let bridge = try await bridge()
        let metadata = try await fault(bridge) { with($0, "aud", "some-other-client") }

        let reason = try await rejected(bridge)

        XCTAssertEqual(reason, "audience")
        try await assertNothingPersisted(bridge, metadata)
    }

    func test27CATwoElementAudWithoutAzpIsRejectedAsAudience() async throws {
        let bridge = try await bridge()
        let metadata = try await fault(bridge) { without(with($0, "aud", [Provider.clientId, "some-other-client"]), "azp") }

        let reason = try await rejected(bridge)

        XCTAssertEqual(reason, "audience")
        try await assertNothingPersisted(bridge, metadata)
    }

    func test27DExpInThePastByTheServersDateHeaderBeyondTheToleranceIsRejectedAsExpired() async throws {
        let bridge = try await bridge()
        let now = Date()
        let exp = Int(now.timeIntervalSince1970) - 120
        let metadata = try await fault(bridge) { with($0, "exp", exp) }
        network.addHeaders(path(metadata.tokenEndpoint), ["Date": httpDate(now)])

        let reason = try await rejected(bridge)

        XCTAssertEqual(reason, "expired")
        try await assertNothingPersisted(bridge, metadata)
    }

    func test27DATokenLiveByTheServersDateHeaderIsAcceptedAlthoughTheDeviceClockWouldExpireIt() async throws {
        let bridge = try await bridge()
        let serverNow = Date().addingTimeInterval(-600)
        let seconds = Int(serverNow.timeIntervalSince1970)
        let metadata = try await fault(bridge) { with($0, "iat", seconds, "auth_time", seconds, "exp", seconds + 60) }
        network.addHeaders(path(metadata.tokenEndpoint), ["Date": httpDate(serverNow)])

        try ok(await bridge.dart.login())

        let state = try await bridge.dart.sessionState()
        XCTAssertEqual(state, .authenticated)
        let claims = try await bridge.dart.claims()
        XCTAssertEqual(claims?.expiresAtEpochSeconds, Int64(seconds + 60))
    }

    func test27EAMissingIatIsRejectedAsIssuedAt() async throws {
        let bridge = try await bridge()
        let metadata = try await fault(bridge) { without($0, "iat") }

        let reason = try await rejected(bridge)

        XCTAssertEqual(reason, "issuedAt")
        try await assertNothingPersisted(bridge, metadata)
    }

    func test27FAuthTimeOlderThanTheMaxAgeRequestedIsRejectedAsAuthTime() async throws {
        let bridge = try await bridge()
        let old = Int(Date().timeIntervalSince1970) - 3600
        let metadata = try await fault(bridge) { with($0, "auth_time", old) }

        let reason = try await rejected(bridge, DartSide.loginOptions(maxAge: 60))

        XCTAssertEqual(reason, "authTime")
        try await assertNothingPersisted(bridge, metadata)
    }

    /// RFC 1123 in GMT, as an HTTP `Date` header.
    private func httpDate(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "GMT")
        formatter.dateFormat = "EEE, dd MMM yyyy HH:mm:ss 'GMT'"
        return formatter.string(from: date)
    }
}

/// `payload` with each `key, value` pair set.
private func with(_ payload: [String: Any], _ pairs: Any...) -> [String: Any] {
    var copy = payload
    var index = 0
    while index + 1 < pairs.count {
        copy[pairs[index] as! String] = pairs[index + 1]
        index += 2
    }
    return copy
}

private func without(_ payload: [String: Any], _ key: String) -> [String: Any] {
    var copy = payload
    copy.removeValue(forKey: key)
    return copy
}
