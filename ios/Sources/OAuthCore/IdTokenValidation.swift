import CryptoKit
import Foundation

/// The ID-token checks of OpenID Connect Core 3.1.3.7 and 12.2, in the order of
/// `spec/oauth-sdk-api.md` section 11. Every refusal is `configuration(.idTokenRejected(reason))`;
/// a provider that cannot be reached for its keys is `recoverable(.network)` and one that
/// advertises no `jwks_uri` is `configuration(.providerUnsupported("jwks_uri"))`, both raised
/// before any claim is read, so a token is never half-judged.
///
/// Fail closed throughout: nothing here has an off switch, and a claim that is present but of
/// the wrong type is `.malformed` rather than ignored.
public struct JwksIdTokenValidator: IdTokenValidator {
    private let issuer: @Sendable () async throws -> String
    private let clientId: String
    private let verifier: JwsVerifier
    private let clockSkewTolerance: TimeInterval
    private let clock: Clock

    /// - Parameters:
    ///   - issuer: compared byte for byte with `iss`; supplied from discovery, since that is the
    ///     value the provider signs tokens under (a configured value may differ by a trailing
    ///     slash, which discovery tolerates and this check must not). Discovery's check guards
    ///     where a document was fetched from, this one guards who signed a token, and a provider
    ///     that issues `https://a/` and `https://a` is two issuers.
    ///   - jwksUri: the `jwks_uri` from discovery, nil when it advertises none.
    ///   - allowedAlgorithms: the provider's `id_token_signing_alg_values_supported`; empty means
    ///     it did not say, and the closed asymmetric set alone applies.
    ///   - clockSkewTolerance: how far the device clock may be from the provider's; applied to
    ///     `exp`, `iat` and `auth_time`.
    ///   - clock: the injected time source, never read directly.
    public init(
        issuer: @escaping @Sendable () async throws -> String,
        clientId: String,
        jwksUri: @escaping @Sendable () async throws -> String?,
        allowedAlgorithms: @escaping @Sendable () async throws -> [String],
        jwks: JwksClient,
        clockSkewTolerance: TimeInterval = 60,
        clock: Clock = .system
    ) {
        self.issuer = issuer
        self.clientId = clientId
        self.verifier = JwsVerifier(jwksUri: jwksUri, allowedAlgorithms: allowedAlgorithms, jwks: jwks)
        self.clockSkewTolerance = clockSkewTolerance
        self.clock = clock
    }

    public func validate(
        idToken: String,
        expectedNonce: String?,
        accessToken: String?,
        maxAge: Int?,
        previous: IdTokenClaims?,
        serverTime: Date?
    ) async throws -> IdTokenClaims {
        let token: ParsedJws
        do {
            token = try await verifier.verify(idToken)
        } catch let rejection as JwsRejection {
            throw OAuthError.configuration(.idTokenRejected(rejection.reason))
        }
        let expectedIssuer = try await issuer()
        do {
            return try check(token, expectedNonce, accessToken, maxAge, previous, expectedIssuer, serverTime)
        } catch let rejection as JwsRejection {
            throw OAuthError.configuration(.idTokenRejected(rejection.reason))
        }
    }

    private func check(
        _ token: ParsedJws,
        _ expectedNonce: String?,
        _ accessToken: String?,
        _ maxAge: Int?,
        _ previous: IdTokenClaims?,
        _ issuer: String,
        _ serverTime: Date?
    ) throws -> IdTokenClaims {
        let claims = token.claims
        // The provider's own clock when it has just told us (the token response's `Date`): the
        // token was minted against that clock, so a device clock minutes off does not turn every
        // `iat` into "the future". Otherwise the injected clock.
        let now = serverTime ?? clock.now()
        let tolerance = clockSkewTolerance

        // Types first, so that a claim of the wrong type is `.malformed` wherever it sits in the
        // order below; whether a value is acceptable is decided by the checks that follow.
        let iss = try ClaimReader.text(claims, "iss")
        guard let sub = try ClaimReader.text(claims, "sub") else { throw JwsRejection(.malformed, "no sub") }
        let audience = try ClaimReader.audience(claims)
        let authorizedParty = try ClaimReader.text(claims, "azp")
        guard let exp = try ClaimReader.time(claims, "exp") else { throw JwsRejection(.malformed, "no exp") }
        let iat = try ClaimReader.time(claims, "iat")
        let nonce = try ClaimReader.text(claims, "nonce")
        let authTime = try ClaimReader.time(claims, "auth_time")
        let acr = try ClaimReader.text(claims, "acr")
        let amr = try ClaimReader.textList(claims, "amr")
        let atHash = try ClaimReader.text(claims, "at_hash")

        // Core 3.1.3.7 step 2 and 3.
        if iss != issuer { throw JwsRejection(.issuer, "iss is not the issuer") }

        // Steps 3 and 4. azp is checked whenever present, not only with several audiences: the
        // spec's SHOULD costs nothing, and an ID token issued to another party is not for us.
        guard let audience, audience.contains(clientId) else {
            throw JwsRejection(.audience, "aud does not contain the client id")
        }
        if audience.count > 1 && authorizedParty == nil { throw JwsRejection(.audience, "several audiences and no azp") }
        if let authorizedParty, authorizedParty != clientId { throw JwsRejection(.audience, "azp is not the client id") }

        // Step 9: exp in the future, with the skew tolerance in the token's favour.
        if !(exp.addingTimeInterval(tolerance) > now) { throw JwsRejection(.expired, "exp has passed") }

        // iat must exist and must not lie in the future beyond the tolerance. A token issued
        // "tomorrow" is a clock the provider and the device disagree about, or a forgery. How old
        // it is is bounded by exp rather than by a second window here: providers legitimately
        // return a refreshed token whose iat predates the call by seconds, and an arbitrary age
        // cap would reject them.
        guard let iat else { throw JwsRejection(.issuedAt, "no iat") }
        if iat > now.addingTimeInterval(tolerance) { throw JwsRejection(.issuedAt, "iat is in the future") }

        // Step 11, login only (a refresh passes nil and a nonce it carries is ignored). A
        // constant-time compare, not `==`: the nonce is a secret the request put on the wire, and
        // an early-exit compare leaks how much of it matched.
        if let expectedNonce {
            guard let nonce, JoseConstantTime.equals(nonce, expectedNonce) else {
                throw JwsRejection(.nonce, "nonce is missing or not the request's")
            }
        }

        // Step 12: under max_age, auth_time is required and must be recent enough. The tolerance
        // is added to the window, otherwise max_age=0 could never be met by a login that took a
        // second.
        if let maxAge {
            guard let authTime else { throw JwsRejection(.authTime, "no auth_time under max_age") }
            if authTime < now.addingTimeInterval(-TimeInterval(maxAge) - tolerance) {
                throw JwsRejection(.authTime, "auth_time is older than max_age")
            }
        }

        // Refresh (Core 12.2): the new token must be about the same user and no earlier
        // authentication. The enum has no case for a changed subject, so it is `.malformed`, as on
        // Android: the token is not a refresh of that session, a statement about its shape (it
        // names someone else) rather than about any one claim check. A refresh token swapped to
        // another account's is exactly the case this exists for.
        if let previous {
            if sub != previous.subject { throw JwsRejection(.malformed, "sub changed on refresh") }
            // A refreshed token may omit auth_time (12.2); one that carries it must not claim an
            // earlier authentication than the token it replaces.
            if let authTime, let before = previous.authTime, authTime < before {
                throw JwsRejection(.authTime, "auth_time moved backwards on refresh")
            }
        }

        // Core 3.1.3.6: base64url of the left half of the hash of the access token, the hash being
        // the one the JWS algorithm uses. Optional in the code flow, so absent is fine; present
        // and wrong is not.
        if let atHash, let accessToken, let algorithm = token.alg.flatMap(JwsAlgorithm.init(rawValue:)) {
            let digest = Self.digest(Data(accessToken.utf8), bytes: algorithm.digestBytes)
            let expected = JoseBase64Url.encode(digest.prefix(digest.count / 2))
            if !JoseConstantTime.equals(atHash, expected) {
                throw JwsRejection(.accessTokenHash, "at_hash does not match the access token")
            }
        }

        // The typed claims are above; everything else is for an app reading provider-specific
        // ones. The nonce is spent by this validation and is not exposed.
        let typed: Set<String> = ["iss", "sub", "aud", "iat", "exp", "auth_time", "acr", "amr", "nonce"]
        return IdTokenClaims(
            subject: sub,
            issuer: iss ?? issuer,
            audience: audience,
            issuedAt: iat,
            expiresAt: exp,
            authTime: authTime,
            acr: acr,
            amr: amr ?? [],
            additional: claims.filter { !typed.contains($0.key) }.mapValues { $0.claimText }
        )
    }

    private static func digest(_ data: Data, bytes: Int) -> Data {
        switch bytes {
        case 32: return Data(SHA256.hash(data: data))
        case 48: return Data(SHA384.hash(data: data))
        default: return Data(SHA512.hash(data: data))
        }
    }
}

/// The claims of an ID token that was validated before it was stored, read back without
/// re-verifying: after process death a stored grant restores `authenticated`, and the app's
/// `claims` and the refresh check against the previous `sub` need the values the token carried.
public enum IdTokenClaimsParser {
    /// Nothing here is trusted beyond what the original validation proved, and `exp` of an ID
    /// token says nothing about the session, so a missing time is the epoch rather than a
    /// failure. Lenient on purpose: a store that only holds what the SDK wrote never produces
    /// a token this refuses.
    ///
    /// - Throws: `JwsRejection(.malformed)` when the token no longer parses or has no `sub` or `iss`.
    public static func parseStored(_ idToken: String) throws -> IdTokenClaims {
        let claims = try Jws.parse(idToken).claims
        func text(_ name: String) -> String? {
            if case .string(let value)? = claims[name] { return value }
            return nil
        }
        func time(_ name: String) -> Date? {
            claims[name]?.numeric.map { Date(timeIntervalSince1970: $0) }
        }
        func list(_ name: String) -> [String] {
            switch claims[name] {
            case .array(let items)?:
                return items.compactMap { if case .string(let value) = $0 { return value } else { return nil } }
            case .string(let value)?:
                return [value]
            default:
                return []
            }
        }
        guard let subject = text("sub"), let issuer = text("iss") else {
            throw JwsRejection(.malformed, "stored ID token has no sub or iss")
        }
        let typed: Set<String> = ["iss", "sub", "aud", "iat", "exp", "auth_time", "acr", "amr", "nonce"]
        return IdTokenClaims(
            subject: subject,
            issuer: issuer,
            audience: list("aud"),
            issuedAt: time("iat") ?? Date(timeIntervalSince1970: 0),
            expiresAt: time("exp") ?? Date(timeIntervalSince1970: 0),
            authTime: time("auth_time"),
            acr: text("acr"),
            amr: list("amr"),
            additional: claims.filter { !typed.contains($0.key) }.mapValues { $0.claimText }
        )
    }
}

/// Typed reads of a claims set: absent is nil, present but of the wrong type is `.malformed`.
enum ClaimReader {
    static func text(_ claims: [String: JoseJSON], _ name: String) throws -> String? {
        guard let value = claims[name] else { return nil }
        guard case .string(let text) = value else { throw JwsRejection(.malformed, "\(name) is not a string") }
        return text
    }

    static func textList(_ claims: [String: JoseJSON], _ name: String) throws -> [String]? {
        guard let value = claims[name] else { return nil }
        guard case .array(let items) = value else { throw JwsRejection(.malformed, "\(name) is not an array") }
        return try items.map {
            guard case .string(let text) = $0 else { throw JwsRejection(.malformed, "\(name) holds a non-string") }
            return text
        }
    }

    /// `aud` is a string or an array of strings (RFC 7519 4.1.3).
    static func audience(_ claims: [String: JoseJSON]) throws -> [String]? {
        guard let value = claims["aud"] else { return nil }
        if case .array = value { return try textList(claims, "aud") }
        return try text(claims, "aud").map { [$0] }
    }

    /// Seconds since the epoch as a JSON number (RFC 7519 2, NumericDate); a string is not one.
    static func time(_ claims: [String: JoseJSON], _ name: String) throws -> Date? {
        guard let value = claims[name] else { return nil }
        guard let seconds = value.numeric, seconds.isFinite else { throw JwsRejection(.malformed, "\(name) is not a number") }
        return Date(timeIntervalSince1970: seconds)
    }
}
