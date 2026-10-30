import CryptoKit
import Foundation
import XCTest
import os
@testable import OAuthClient
@testable import OAuthCore

/// Why a DPoP-verifying resource server refused a request: one value per check of RFC 9449
/// section 7.1 / 4.3, mirroring the Android driver's `DpopRefusal`. A negative test asserts the
/// reason, not only the 401: a request refused for the wrong reason has not shown that the right
/// check exists.
enum DpopRefusal: Sendable, Equatable {
    case noAuthorization
    /// The token was presented under a scheme other than `DPoP` (RFC 9449 section 7.1).
    case wrongScheme
    case noProof
    case multipleProofs
    case tokenMalformed, tokenSignature, tokenIssuer, tokenExpired
    /// The access token carries no `cnf.jkt`: it is not sender-constrained.
    case tokenNotBound
    case proofMalformed, proofType, proofAlgorithm, proofKey, proofSignature
    case method, url, issuedAt, replayedJti, accessTokenHash
    /// The proof is valid but its key is not the one the token is bound to (`cnf.jkt`).
    case keyMismatch
    case nonceRequired
}

enum DpopVerdict: Sendable, Equatable {
    /// `jkt` is the thumbprint of the proof's key, equal to the token's `cnf.jkt` by the time it is accepted.
    case accepted(jkt: String, subject: String)
    case refused(DpopRefusal)
}

/// A protected resource on a virtual origin that verifies DPoP the way RFC 9449 section 7 asks of
/// one, so what the SDK sends is judged by a party holding nothing but the provider's public keys
/// (the Android driver's `DpopResourceServer`, ported):
///
/// - the access token: an RS256 JWT signed by a key of the provider's JWKS, issued by the issuer
///   the SDK was configured with (the proxy's), not expired, carrying `cnf.jkt`. The signature
///   is checked with the SDK's own `JwsSignatures` because RS256 over a JWK is not what this
///   scenario tests and CryptoKit has no RSA; everything about the proof is checked here;
/// - the scheme is `DPoP`, never `Bearer`, with exactly one `DPoP` header (`URLSession` joins
///   repeated headers with ", ", which no JWT contains, so a comma means more than one);
/// - the proof: `typ` `dpop+jwt`, `alg` `ES256`, a public EC P-256 `jwk` without a private member,
///   a signature that verifies under it, `htm`, `htu` (the URL without query and fragment), `iat`
///   within `window` seconds, a `jti` never seen, `ath` the base64url SHA-256 of the token, and
///   the `jwk`'s thumbprint equal to `cnf.jkt`;
/// - with a nonce set, a proof that does not carry it is answered `401 use_dpop_nonce` with a
///   `DPoP-Nonce` header (section 8).
///
/// Independent of the SDK's proof code: it shares no type with `DpopProofFactory`.
final class DpopResourceServer: Sendable {
    struct Attempt: Sendable {
        let request: URLRequest
        let verdict: DpopVerdict
    }

    private struct State: Sendable {
        var attempts: [Attempt] = []
        var seenJti: Set<String> = []
    }

    private let state = OSAllocatedUnfairLock(initialState: State())
    private let origin: String
    private let issuer: String
    private let jwks: [JsonWebKey]
    private let nonce: String?
    private let offered: String?
    private let window: TimeInterval

    var attempts: [Attempt] { state.withLock { $0.attempts } }
    func verdicts(_ path: String) -> [DpopVerdict] { attempts.filter { $0.request.url?.path == path }.map(\.verdict) }
    func url(_ path: String) -> String { origin + path }

    /// Registers the server on `origin` of the virtual network. `offered` is the nonce the 401
    /// hands out, `nonce` unless a test wants a server that offers one it will not accept.
    static func install(
        _ network: VirtualNetwork, origin: String, nonce: String? = nil, offered: String? = nil, window: TimeInterval = 60
    ) async throws -> DpopResourceServer {
        let provider = VirtualNetwork.shared.provider!
        let (discovery, _) = try await URLSession.shared.data(from: URL(string: provider.issuer + "/.well-known/openid-configuration")!)
        guard let object = (try? JSONSerialization.jsonObject(with: discovery)) as? [String: Any], let jwksUri = object["jwks_uri"] as? String else {
            throw ConformanceFailure("the provider advertises no jwks_uri; the resource server cannot verify tokens")
        }
        let (keys, _) = try await URLSession.shared.data(from: URL(string: jwksUri)!)
        let set = try JSONDecoder().decode(JsonWebKeySet.self, from: keys)
        let server = DpopResourceServer(
            origin: origin, issuer: Provider.proxyOrigin + provider.issuerPath, jwks: set.keys.filter { $0.kty == "RSA" && $0.use != "enc" },
            nonce: nonce, offered: offered ?? nonce, window: window
        )
        network.resource(origin) { request in server.answer(request) }
        return server
    }

    private init(origin: String, issuer: String, jwks: [JsonWebKey], nonce: String?, offered: String?, window: TimeInterval) {
        self.origin = origin
        self.issuer = issuer
        self.jwks = jwks
        self.nonce = nonce
        self.offered = offered
        self.window = window
    }

    private func answer(_ request: URLRequest) -> VirtualNetwork.StubAnswer {
        let verdict = verify(request)
        state.withLock { $0.attempts.append(Attempt(request: request, verdict: verdict)) }
        switch verdict {
        case .accepted(let jkt, let subject):
            return VirtualNetwork.StubAnswer(status: 200, headers: ["Content-Type": "application/json"], body: Data("{\"sub\":\"\(subject)\",\"jkt\":\"\(jkt)\"}".utf8))
        case .refused(.nonceRequired):
            return VirtualNetwork.StubAnswer(status: 401, headers: ["WWW-Authenticate": "DPoP error=\"use_dpop_nonce\", algs=\"ES256\"", "DPoP-Nonce": offered ?? ""])
        case .refused(.noAuthorization), .refused(.wrongScheme), .refused(.noProof), .refused(.multipleProofs):
            return VirtualNetwork.StubAnswer(status: 401, headers: ["WWW-Authenticate": "DPoP algs=\"ES256\""])
        case .refused(.tokenMalformed), .refused(.tokenSignature), .refused(.tokenIssuer), .refused(.tokenExpired), .refused(.tokenNotBound):
            return VirtualNetwork.StubAnswer(status: 401, headers: ["WWW-Authenticate": "DPoP error=\"invalid_token\", algs=\"ES256\""])
        case .refused:
            return VirtualNetwork.StubAnswer(status: 401, headers: ["WWW-Authenticate": "DPoP error=\"invalid_dpop_proof\", algs=\"ES256\""])
        }
    }

    private func verify(_ request: URLRequest) -> DpopVerdict {
        guard let authorization = request.value(forHTTPHeaderField: "Authorization") else { return .refused(.noAuthorization) }
        let scheme = authorization.split(separator: " ", maxSplits: 1).first.map(String.init) ?? ""
        let tokenValue = authorization.split(separator: " ", maxSplits: 1).dropFirst().first.map(String.init) ?? ""

        // The token first, whatever the scheme: a refusal for the scheme is only a statement about
        // binding when the token really is a bound one.
        guard let token = Self.parts(tokenValue), let tokenHeader = Self.decode(token[0]), let claims = Self.decode(token[1]) else { return .refused(.tokenMalformed) }
        guard tokenHeader["alg"] as? String == "RS256", let key = jwks.first(where: { $0.kid == tokenHeader["kid"] as? String }),
              let signature = Base64Url.decode(token[2]),
              JwsSignatures.verifies(algorithm: .RS256, key: key, signingInput: Data("\(token[0]).\(token[1])".utf8), signature: signature)
        else { return .refused(.tokenSignature) }
        if claims["iss"] as? String != issuer { return .refused(.tokenIssuer) }
        if (claims["exp"] as? Double ?? 0) <= Date().timeIntervalSince1970 { return .refused(.tokenExpired) }
        guard let boundTo = (claims["cnf"] as? [String: Any])?["jkt"] as? String else { return .refused(.tokenNotBound) }

        if scheme != "DPoP" { return .refused(.wrongScheme) }
        guard let header = request.value(forHTTPHeaderField: "DPoP") else { return .refused(.noProof) }
        if header.contains(",") { return .refused(.multipleProofs) }

        guard let proof = Self.parts(header), let proofHeader = Self.decode(proof[0]), let body = Self.decode(proof[1]) else { return .refused(.proofMalformed) }
        if proofHeader["typ"] as? String != "dpop+jwt" { return .refused(.proofType) }
        if proofHeader["alg"] as? String != "ES256" { return .refused(.proofAlgorithm) }
        // A private member in a proof's jwk is a key leak, and a proof that carries one is refused.
        guard let jwk = proofHeader["jwk"] as? [String: Any], jwk["kty"] as? String == "EC", jwk["crv"] as? String == "P-256", jwk["d"] == nil,
              let x = (jwk["x"] as? String).flatMap(Base64Url.decode), let y = (jwk["y"] as? String).flatMap(Base64Url.decode), x.count == 32, y.count == 32,
              let publicKey = try? P256.Signing.PublicKey(x963Representation: Data([4]) + x + y)
        else { return .refused(.proofKey) }
        guard let raw = Base64Url.decode(proof[2]), let ecdsa = try? P256.Signing.ECDSASignature(rawRepresentation: raw),
              publicKey.isValidSignature(ecdsa, for: Data("\(proof[0]).\(proof[1])".utf8))
        else { return .refused(.proofSignature) }

        if body["htm"] as? String != request.httpMethod { return .refused(.method) }
        // The target URI as this server saw it, minus query and fragment (RFC 9449 section 4.2).
        var target = URLComponents(url: request.url!, resolvingAgainstBaseURL: false)!
        target.query = nil
        target.fragment = nil
        if body["htu"] as? String != target.string { return .refused(.url) }
        guard let issuedAt = body["iat"] as? Double, abs(Date().timeIntervalSince1970 - issuedAt) <= window else { return .refused(.issuedAt) }
        if body["ath"] as? String != Self.sha256Url(tokenValue) { return .refused(.accessTokenHash) }
        if Self.thumbprint(x: jwk["x"] as! String, y: jwk["y"] as! String) != boundTo { return .refused(.keyMismatch) }
        guard let jti = body["jti"] as? String, !jti.isEmpty else { return .refused(.proofMalformed) }
        if !state.withLock({ $0.seenJti.insert(jti).inserted }) { return .refused(.replayedJti) }
        if let nonce, body["nonce"] as? String != nonce { return .refused(.nonceRequired) }

        return .accepted(jkt: boundTo, subject: claims["sub"] as? String ?? "")
    }


    /// What the binding is for: the access token `token`, once stolen, is useless without the key.
    /// Each case changes exactly one thing from a request this server accepts (the control), so the
    /// refusal is that check's and nothing else's; the verdict's reason, not only the 401, is
    /// asserted. `sdkKey` is the SDK's own key as the harness reached it, so a case that changes one
    /// claim of the SDK's proof is that claim's check and not a forger's mistake. Shared by the native
    /// driver and the Flutter bridge's: both hold a token and the key, and neither needs the SDK to
    /// make the request.
    func assertStolenTokenIsRefused(token: String, sdkKey: P256.Signing.PrivateKey) async throws {
        let attacker = P256.Signing.PrivateKey()
        let session = VirtualNetwork.session(record: false)
        let target = url("/api")

        func send(path: String = "/api", method: String = "GET", authorization: String? = "DPoP \(token)", proofs: [String] = []) async throws -> DpopVerdict {
            var request = URLRequest(url: URL(string: url(path))!)
            request.httpMethod = method
            if let authorization { request.setValue(authorization, forHTTPHeaderField: "Authorization") }
            // URLSession joins repeated headers; the server reads a comma as "more than one".
            for proof in proofs { request.addValue(proof, forHTTPHeaderField: "DPoP") }
            let before = attempts.count
            let (_, response) = try await session.data(for: request)
            XCTAssertEqual(attempts.count - before, 1)
            let verdict = try XCTUnwrap(attempts.last?.verdict)
            if case .accepted = verdict { XCTAssertEqual((response as? HTTPURLResponse)?.statusCode, 200) } else { XCTAssertEqual((response as? HTTPURLResponse)?.statusCode, 401) }
            return verdict
        }
        func refused(_ label: String, _ reason: DpopRefusal, _ verdict: DpopVerdict, line: UInt = #line) {
            XCTAssertEqual(verdict, .refused(reason), label, line: line)
        }
        func proof(_ key: P256.Signing.PrivateKey, method: String = "GET", url other: String? = nil, issuedAt: Double = Date().timeIntervalSince1970, ath: String?? = nil) -> String {
            DpopResourceServer.forgeProof(key, method: method, url: other ?? target, accessToken: token, issuedAt: issuedAt, ath: ath)
        }

        // The control: the SDK's own key, every claim right. Accepted, so what follows is not the forger's fault.
        let control = try await send(proofs: [proof(sdkKey)])
        guard case .accepted = control else { return XCTFail("control: \(control)") }

        let swapped = DpopResourceServer.forgeProof(sdkKey, method: "GET", url: target, accessToken: token, signer: attacker)
        refused("the SDK's jwk in the header, a signature by another key", .proofSignature, try await send(proofs: [swapped]))
        refused("the token alone, no proof", .noProof, try await send())
        refused("the token as a Bearer, no proof", .wrongScheme, try await send(authorization: "Bearer \(token)"))
        refused("the token as a Bearer, with a valid proof", .wrongScheme, try await send(authorization: "Bearer \(token)", proofs: [proof(sdkKey)]))
        refused("a proof from another key (every claim right, ath included)", .keyMismatch, try await send(proofs: [proof(attacker)]))
        refused("the SDK's key, but ath of another token", .accessTokenHash, try await send(proofs: [proof(sdkKey, ath: .some(DpopResourceServer.sha256Url("another-token")))]))
        refused("the SDK's key, but no ath", .accessTokenHash, try await send(proofs: [proof(sdkKey, ath: .some(nil))]))
        refused("the SDK's key, but a proof for another URL", .url, try await send(proofs: [proof(sdkKey, url: url("/api/other"))]))
        refused("the SDK's key, but a proof for another method", .method, try await send(proofs: [proof(sdkKey, method: "POST")]))
        refused("the SDK's key, but a proof ten minutes old", .issuedAt, try await send(proofs: [proof(sdkKey, issuedAt: Date().timeIntervalSince1970 - 600)]))
        refused("two proofs", .multipleProofs, try await send(proofs: [proof(sdkKey), proof(sdkKey)]))

        // Re-binding the stolen token to the thief's key: change cnf.jkt, keep the provider's signature.
        let parts = token.split(separator: ".").map(String.init)
        var payload = Self.decode(parts[1]) ?? [:]
        var cnf = try XCTUnwrap(payload["cnf"] as? [String: Any])
        cnf["jkt"] = DpopResourceServer.thumbprint(attacker.publicKey)
        payload["cnf"] = cnf
        let tampered = "\(parts[0]).\(Base64Url.encode(try JSONSerialization.data(withJSONObject: payload))).\(parts[2])"
        refused(
            "the token re-bound to the thief's key", .tokenSignature,
            try await send(authorization: "DPoP \(tampered)", proofs: [DpopResourceServer.forgeProof(attacker, method: "GET", url: target, accessToken: tampered)])
        )
    }

    // MARK: Helpers shared with the scenario

    static func parts(_ jwt: String) -> [String]? {
        let parts = jwt.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        return parts.count == 3 ? parts : nil
    }

    static func decode(_ segment: String) -> [String: Any]? {
        Base64Url.decode(segment).flatMap { (try? JSONSerialization.jsonObject(with: $0)) as? [String: Any] }
    }

    static func sha256Url(_ value: String) -> String { Base64Url.encode(Data(SHA256.hash(data: Data(value.utf8)))) }

    /// RFC 7638: SHA-256 over the required members in lexicographic order, no whitespace.
    static func thumbprint(x: String, y: String) -> String {
        sha256Url(#"{"crv":"P-256","kty":"EC","x":"\#(x)","y":"\#(y)"}"#)
    }

    static func jwk(_ key: P256.Signing.PublicKey) -> (x: String, y: String) {
        let point = key.x963Representation
        return (Base64Url.encode(point.subdata(in: 1..<33)), Base64Url.encode(point.subdata(in: 33..<65)))
    }

    static func thumbprint(_ key: P256.Signing.PublicKey) -> String {
        let (x, y) = jwk(key)
        return thumbprint(x: x, y: y)
    }

    /// A proof signed with `key`, the way the SDK's own would be, with the claims the caller chooses:
    /// the attacker's tool and the control group in one. A proof with every claim right is accepted,
    /// so a refusal of one with a single claim wrong is that claim's check and not the forger's.
    /// `ath: .some(nil)` omits the claim; the default hashes `accessToken`.
    static func forgeProof(
        _ key: P256.Signing.PrivateKey, method: String, url: String, accessToken: String?,
        issuedAt: Double = Date().timeIntervalSince1970, jti: String = UUID().uuidString, nonce: String? = nil, ath: String?? = nil,
        /// Signs with this key instead of `key`'s while the header still carries `key`'s `jwk`: a proof whose signature is not its sender's.
        signer: P256.Signing.PrivateKey? = nil
    ) -> String {
        let (x, y) = jwk(key.publicKey)
        let header: [String: Any] = ["typ": "dpop+jwt", "alg": "ES256", "jwk": ["kty": "EC", "crv": "P-256", "x": x, "y": y]]
        var claims: [String: Any] = ["htm": method, "htu": String(url.split(separator: "?").first ?? ""), "iat": Int(issuedAt), "jti": jti]
        if let nonce { claims["nonce"] = nonce }
        switch ath {
        case .none: if let accessToken { claims["ath"] = sha256Url(accessToken) }
        case .some(.some(let value)): claims["ath"] = value
        case .some(.none): break
        }
        let input = "\(Base64Url.encode(try! JSONSerialization.data(withJSONObject: header))).\(Base64Url.encode(try! JSONSerialization.data(withJSONObject: claims)))"
        let signature = try! (signer ?? key).signature(for: Data(input.utf8))
        return "\(input).\(Base64Url.encode(signature.rawRepresentation))"
    }
}

/// Where the SDK's DPoP key persists in a driver run: in memory, because an unsigned host's
/// Keychain refuses it (-34018) and a test's key must not outlive the test. It is also how the
/// harness reaches the key the SDK generated, to sign what that key would sign with claims of its
/// own choosing (`DpopResourceServer.forgeProof`); a real Keychain never hands a key out, this is
/// a test fixture.
final class InMemoryDpopKeyStore: DpopKeyStore {
    private let stored = OSAllocatedUnfairLock<Data?>(initialState: nil)
    func load() throws -> Data? { stored.withLock { $0 } }
    func save(_ data: Data) throws { stored.withLock { $0 = data } }
    func delete() throws { stored.withLock { $0 = nil } }

    /// The software key the SDK generated (tag byte 2, then the raw private key), or nil when none exists.
    var softwareKey: P256.Signing.PrivateKey? {
        guard let data = stored.withLock({ $0 }), data.first == 2 else { return nil }
        return try? P256.Signing.PrivateKey(rawRepresentation: data.dropFirst())
    }
}

extension TranscriptEntry {
    /// The DPoP proof's header and claims, when the request carried one.
    var proofHeader: [String: Any]? { header("DPoP").flatMap(DpopResourceServer.parts).flatMap { DpopResourceServer.decode($0[0]) } }
    var proofClaims: [String: Any]? { header("DPoP").flatMap(DpopResourceServer.parts).flatMap { DpopResourceServer.decode($0[1]) } }
}
