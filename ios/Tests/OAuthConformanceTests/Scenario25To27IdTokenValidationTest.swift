import Foundation
@testable import OAuthCore
import XCTest
@testable import OAuthClient

/// `25-id-token-nonce-mismatch`, `26-id-token-signature-invalid` and `27-id-token-claims-rejected`:
/// the proxy re-signs the provider's ID token with the harness's key, served from a substituted
/// JWKS, so that only the claim under test is wrong; the SDK must refuse with the matching
/// reason, persist nothing and settle on the state it had. The twin of the Android driver's
/// `Scenario25To27IdTokenValidationTest`, test for test.
///
/// Case D of scenario 27 moves the server's clock rather than the device's: the device clock
/// cannot be moved from a test, and the `Date` header the proxy adds is how the SDK learns the
/// server's time, so a token that is expired by the device clock but live by the server's is
/// accepted, and one expired by both is not.
final class Scenario25To27IdTokenValidationTest: ProviderConformance {
    private let signer = HarnessSigner()

    /// Installs the harness JWKS and an ID-token rewrite; returns the metadata the paths came from.
    private func fault(
        _ client: OAuthClient, alg: String = "RS256", mutate: @escaping @Sendable ([String: Any]) -> [String: Any]
    ) async throws -> ProviderMetadata {
        let metadata = try await client.metadata()
        let signer = self.signer
        network.rewrite(path(metadata.jwksUri)) { _ in signer.jwks() }
        network.rewriteJSON(path(metadata.tokenEndpoint)) { response in
            guard let idToken = response["id_token"] as? String else { return response }
            return HarnessSigner.withIdToken(response, signer.resign(idToken, alg: alg, mutate: mutate))
        }
        return metadata
    }

    private func rejected(_ client: OAuthClient, _ options: LoginOptions = .default, file: StaticString = #filePath, line: UInt = #line) async -> IdTokenRejection? {
        let error = await oauthError(file: file, line: line) { try await client.login(options) }
        guard case .configuration(.idTokenRejected(let reason))? = error else {
            XCTFail("expected configuration(idTokenRejected), got \(String(describing: error))", file: file, line: line)
            return nil
        }
        return reason
    }

    /// `since`: the transcript's size when the fault was installed; what came before is not the rejection's.
    private func assertNothingPersisted(_ client: OAuthClient, _ metadata: ProviderMetadata, since: Int = 0, file: StaticString = #filePath, line: UInt = #line) async throws {
        let state = await client.sessionState
        XCTAssertEqual(state, .unauthenticated, file: file, line: line)
        let claims = await client.claims
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
        let error = await oauthError(file: file, line: line) { _ = try await client.accessToken() }
        guard case .reauthenticate? = error else { return XCTFail("expected reauthenticate, got \(String(describing: error))", file: file, line: line) }
    }

    // MARK: - 25

    func test25NonceMismatchIsRejectedBeforeAnythingIsPersisted() async throws {
        let client = try await client()
        let metadata = try await fault(client) { with($0, "nonce", "not-the-nonce-the-sdk-sent") }

        let reason = await rejected(client)

        XCTAssertEqual(reason, .nonce)
        try await assertNothingPersisted(client, metadata)
    }

    func test25RejectedLoginOverAStoredGrantLeavesTheSessionAuthenticatedAsItWas() async throws {
        let client = try await client()
        try await client.login()
        let claimsBefore = await client.claims
        let subjectBefore = try XCTUnwrap(claimsBefore).subject
        _ = try await fault(client) { without($0, "nonce") }

        let reason = await rejected(client)

        XCTAssertEqual(reason, .nonce)
        let state = await client.sessionState
        XCTAssertEqual(state, .authenticated)
        let claimsAfter = await client.claims
        XCTAssertEqual(claimsAfter?.subject, subjectBefore)
        // The stored grant still works: the access token comes without a new browser.
        _ = try await client.accessToken()
        XCTAssertEqual(browser.opened.count, 2)
    }

    // MARK: - 26

    func test26ASignatureThatDoesNotVerifyIsRejectedAsSignature() async throws {
        let client = try await client()
        let metadata = try await client.metadata()
        // The provider's own keys stay; the token's signature bytes are flipped.
        network.rewriteJSON(path(metadata.tokenEndpoint)) { response in
            guard let idToken = response["id_token"] as? String else { return response }
            let parts = idToken.split(separator: ".").map(String.init)
            guard parts.count == 3, var signature = Base64Url.decode(parts[2]), !signature.isEmpty else { return response }
            signature[signature.startIndex] ^= 0x55
            return HarnessSigner.withIdToken(response, "\(parts[0]).\(parts[1]).\(Base64Url.encode(signature))")
        }

        let reason = await rejected(client)

        XCTAssertEqual(reason, .signature)
        try await assertNothingPersisted(client, metadata)
    }

    func test26BAKeyAbsentFromJwksUriCausesExactlyOneRefetchThenSignature() async throws {
        let client = try await client()
        let metadata = try await client.metadata()
        let jwksPath = path(metadata.jwksUri)
        // Warm the key cache with a real login so the refetch is observable as such.
        try await client.login()
        _ = await client.logout()
        let fetchesBefore = network.matching("GET", jwksPath).count
        let since = network.transcript.count
        let other = HarnessSigner(kid: "absent-from-the-set")
        network.rewriteJSON(path(metadata.tokenEndpoint)) { response in
            guard let idToken = response["id_token"] as? String else { return response }
            return HarnessSigner.withIdToken(response, other.resign(idToken) { $0 })
        }

        let reason = await rejected(client)

        XCTAssertEqual(reason, .signature)
        XCTAssertEqual(network.matching("GET", jwksPath).count - fetchesBefore, 1, "JWKS fetches during the rejected login")
        try await assertNothingPersisted(client, metadata, since: since)
    }

    func test26CAlgNoneWithAnEmptySignatureIsRejectedAsAlgorithmBeforeAnyKeyIsFetched() async throws {
        let client = try await client()
        let metadata = try await fault(client, alg: "none") { $0 }
        let jwksPath = path(metadata.jwksUri)
        let fetchesBefore = network.matching("GET", jwksPath).count

        let reason = await rejected(client)

        XCTAssertEqual(reason, .algorithm)
        XCTAssertEqual(network.matching("GET", jwksPath).count, fetchesBefore)
        try await assertNothingPersisted(client, metadata)
    }

    func test26DHS256SignedWithTheClientIdAsKeyIsRejectedAsAlgorithm() async throws {
        let client = try await client()
        let metadata = try await fault(client, alg: "HS256") { $0 }

        let reason = await rejected(client)

        XCTAssertEqual(reason, .algorithm)
        try await assertNothingPersisted(client, metadata)
    }

    // MARK: - 27

    func test27AIssDifferingByATrailingSlashIsRejectedAsIssuer() async throws {
        let client = try await client()
        let metadata = try await fault(client) { with($0, "iss", (($0["iss"] as? String) ?? "") + "/") }

        let reason = await rejected(client)

        XCTAssertEqual(reason, .issuer)
        try await assertNothingPersisted(client, metadata)
    }

    func test27BAudEqualToAnotherClientIdIsRejectedAsAudience() async throws {
        let client = try await client()
        let metadata = try await fault(client) { with($0, "aud", "some-other-client") }

        let reason = await rejected(client)

        XCTAssertEqual(reason, .audience)
        try await assertNothingPersisted(client, metadata)
    }

    func test27CATwoElementAudWithoutAzpIsRejectedAsAudience() async throws {
        let client = try await client()
        let metadata = try await fault(client) { without(with($0, "aud", [Provider.clientId, "some-other-client"]), "azp") }

        let reason = await rejected(client)

        XCTAssertEqual(reason, .audience)
        try await assertNothingPersisted(client, metadata)
    }

    func test27DExpInThePastByTheServersDateHeaderBeyondTheToleranceIsRejectedAsExpired() async throws {
        let client = try await client()
        let now = Date()
        let exp = Int(now.timeIntervalSince1970) - 120
        let metadata = try await fault(client) { with($0, "exp", exp) }
        network.addHeaders(path(metadata.tokenEndpoint), ["Date": httpDate(now)])

        let reason = await rejected(client)

        XCTAssertEqual(reason, .expired)
        try await assertNothingPersisted(client, metadata)
    }

    func test27DATokenLiveByTheServersDateHeaderIsAcceptedAlthoughTheDeviceClockWouldExpireIt() async throws {
        let client = try await client()
        let serverNow = Date().addingTimeInterval(-600)
        let seconds = Int(serverNow.timeIntervalSince1970)
        let metadata = try await fault(client) { with($0, "iat", seconds, "auth_time", seconds, "exp", seconds + 60) }
        network.addHeaders(path(metadata.tokenEndpoint), ["Date": httpDate(serverNow)])

        try await client.login()

        let state = await client.sessionState
        XCTAssertEqual(state, .authenticated)
        let claims = await client.claims
        XCTAssertEqual(claims?.expiresAt.timeIntervalSince1970, Double(seconds + 60))
    }

    func test27EAMissingIatIsRejectedAsIssuedAt() async throws {
        let client = try await client()
        let metadata = try await fault(client) { without($0, "iat") }

        let reason = await rejected(client)

        XCTAssertEqual(reason, .issuedAt)
        try await assertNothingPersisted(client, metadata)
    }

    func test27FAuthTimeOlderThanTheMaxAgeRequestedIsRejectedAsAuthTime() async throws {
        let client = try await client()
        let old = Int(Date().timeIntervalSince1970) - 3600
        let metadata = try await fault(client) { with($0, "auth_time", old) }

        let reason = await rejected(client, try LoginOptions(maxAge: 60))

        XCTAssertEqual(reason, .authTime)
        try await assertNothingPersisted(client, metadata)
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
