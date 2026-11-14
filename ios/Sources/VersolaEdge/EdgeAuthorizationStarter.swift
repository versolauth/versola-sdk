import Foundation
import OAuthCore

/// Opens the authorization request through edge: `POST /native/start/{clientId}` builds it, pushes it to
/// `/par` with `dpop_jkt` set from the proof on this very call, and hands back the `request_uri` to open,
/// the `state` to expect and the blob that stands in for the verifier. What is persisted before the browser
/// opens is edge's `state` and blob rather than a verifier of the flow's own.
///
/// The authorization endpoint comes from discovery, not from edge's answer: the issuer is the one URL the
/// integrator vouched for. Every native endpoint demands a proof, so there is no bearer variant; an
/// edge-fronted native client is registered with https redirect URIs only, which is refused here rather than
/// at `/par`.
///
/// **Evidence** (`NativeStartAttestation`, versola#423) is asked for after the proof is minted: an App Attest
/// assertion is made for the `jti` of exactly that proof. Edge checks the proof, and its nonce, before it
/// looks at the evidence, so a `use_dpop_nonce` answer never consumes it -- except that an attestation object
/// is made once per key; the retry that follows a challenge carries a new proof and so new evidence, and the
/// key of the object that was not seen is forgotten (`evidenceNotAccepted`) and a new one attested.
/// Nothing here repeats a request that carried evidence for any other reason: its `jti` is single-use. An
/// object refused or lost for any other reason (a network failure, a 5xx) leaves its key marked attested, and
/// the next login is refused once with `this key has not been attested`, which discards it: one failed login
/// instead of a discard on every transient error.
package struct EdgeAuthorizationStarter: AuthorizationStarter {
    private let configuration: CoreConfiguration
    private let startUrl: URL
    private let httpClient: HTTPClient
    private let dpop: DpopProofSource
    private let attestation: (any NativeStartAttestation)?

    /// Edge sets `dpop_jkt` at `/par` from the proof on `/native/start`.
    package var bindsDpopKeyItself: Bool { true }

    package init(
        configuration: CoreConfiguration, edgeBaseUrl: URL, httpClient: HTTPClient, dpop: DpopProofSource,
        attestation: (any NativeStartAttestation)? = nil
    ) throws {
        guard configuration.redirectUri.scheme?.lowercased() == "https" else {
            throw OAuthError.configuration(.invalidConfiguration(
                detail: "the edge back channel needs an https redirect URI (a universal link): an edge-fronted native client is registered with https redirect URIs only"
            ))
        }
        self.configuration = configuration
        self.startUrl = try edgeNativeUrl(edgeBaseUrl, endpoint: "start", clientId: configuration.clientId)
        self.httpClient = httpClient
        self.dpop = dpop
        self.attestation = attestation
    }

    package func start(request: AuthorizationRequest, metadata: ProviderMetadata, now: Date) async throws
        -> StartedAuthorization {
        let origin = DpopOrigin.of(startUrl)
        var nonceAnswered = false
        while true {
            let proof = try await dpop.proof(method: "POST", url: startUrl, nonce: await dpop.nonce(for: origin), accessToken: nil)
            let evidence = try await evidenceFor(proof: proof)
            let body = FormEncoding.body(Self.form(request, redirectUri: configuration.redirectUri.absoluteString) + evidence.map { ($0.name, $0.value) })
            let response = try await send(body: body, proof: proof)
            await dpop.observe(serverDate: response.header("Date"), age: response.header("Age"), origin: origin)
            let nonce = response.header("DPoP-Nonce")
            if let nonce, !nonce.isEmpty { await dpop.observe(nonce: nonce, origin: origin) }
            if (200..<300).contains(response.statusCode) {
                return try started(response.body, request: request, metadata: metadata, now: now)
            }
            if response.statusCode == 401, response.header("WWW-Authenticate").flatMap(wwwAuthenticateError) == "use_dpop_nonce" {
                // An attestation object that this answer did not deliver is spent: its key is not one edge has
                // seen. Whether or not the challenge can be answered, the next request must attest a new key.
                if evidence.contains(where: { $0.name == "attestation_object" }) { await attestation?.evidenceNotAccepted() }
                if nonceAnswered || nonce == nil || nonce!.isEmpty {
                    throw OAuthError.recoverable(.nonceLoop(origin: origin))
                }
                nonceAnswered = true
                continue
            }
            throw await rejected(response)
        }
    }

    private static func form(_ request: AuthorizationRequest, redirectUri: String) -> [(String, String)] {
        var form: [(String, String)] = [("redirect_uri", redirectUri)]
        if !request.scopes.isEmpty { form.append(("scope", request.scopes.joined(separator: " "))) }
        form.append(("nonce", request.nonce))
        if !request.acrValues.isEmpty { form.append(("acr_values", request.acrValues.joined(separator: " "))) }
        if let maxAge = request.maxAge { form.append(("max_age", String(maxAge))) }
        return form
    }

    private func evidenceFor(proof: String) async throws -> [NativeStartField] {
        guard let attestation, let jti = NativeAttestation.jti(ofProof: proof) else { return [] }
        return try await attestation.fields(clientId: configuration.clientId, jkt: try await dpop.thumbprint(), jti: jti)
    }

    private func send(body: Data, proof: String) async throws -> HTTPResponse {
        let request = HTTPRequest(
            method: .post, url: startUrl,
            headers: ["Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded", "DPoP": proof],
            body: body
        )
        do {
            return try await httpClient.send(request)
        } catch let error as OAuthError {
            throw error
        } catch is CancellationError {
            throw CancellationError()
        } catch {
            throw OAuthError.recoverable(.network(detail: "native start failed", attempts: 1, elapsedMillis: 0))
        }
    }

    private struct StartPayload: Decodable {
        let requestUri: String?
        let expiresIn: Int64?
        let state: String?
        let blob: String?
        let tokenEndpoint: String?
        let revocationEndpoint: String?

        enum CodingKeys: String, CodingKey {
            case requestUri = "request_uri", expiresIn = "expires_in", state, blob
            case tokenEndpoint = "token_endpoint", revocationEndpoint = "revocation_endpoint"
        }
    }

    private func started(_ body: Data, request: AuthorizationRequest, metadata: ProviderMetadata, now: Date) throws
        -> StartedAuthorization {
        guard let payload = try? JSONDecoder().decode(StartPayload.self, from: body) else {
            throw OAuthError.configuration(.tokenResponseMalformed(detail: "/native/start answered something other than a start response"))
        }
        func required(_ name: String, _ value: String?) throws -> String {
            guard let value, !value.isEmpty else {
                throw OAuthError.configuration(.tokenResponseMalformed(detail: "/native/start omitted \(name)"))
            }
            return value
        }
        let requestUri = try required("request_uri", payload.requestUri)
        let state = try required("state", payload.state)
        let blob = try required("blob", payload.blob)
        let tokenEndpoint = try required("token_endpoint", payload.tokenEndpoint)
        let revocationEndpoint = try required("revocation_endpoint", payload.revocationEndpoint)
        // Proofs and refresh tokens are about to be sent for whichever of these edge named.
        try ProviderMetadata.requireSecure("token_endpoint", tokenEndpoint)
        try ProviderMetadata.requireSecure("revocation_endpoint", revocationEndpoint)
        let pending = PendingAuthorizationRequest(
            state: state, nonce: request.nonce, codeVerifier: "", scopes: request.scopes,
            redirectUri: configuration.redirectUri.absoluteString, acrValues: request.acrValues,
            maxAge: request.maxAge, createdAt: now,
            // `/native/complete` requires `iss`, and auth always emits it.
            issRequired: true,
            extensions: [
                EdgeExtension.blob: blob,
                EdgeExtension.tokenEndpoint: tokenEndpoint,
                EdgeExtension.revocationEndpoint: revocationEndpoint,
            ]
        )
        let browser = try FormEncoding.withQuery(
            metadata.authorizationEndpoint, [("client_id", configuration.clientId), ("request_uri", requestUri)]
        )
        let expiresAt = payload.expiresIn.flatMap { $0 > 0 ? now.addingTimeInterval(TimeInterval($0)) : nil }
        return StartedAuthorization(pending: pending, browserUri: browser, expiresAt: expiresAt)
    }

    /// `spec/errors.md`, native table: a 404 is edge fronting no such client, 5xx/408/429 the network's,
    /// a 400 auth's `/par` refusal relayed (or edge's own `invalid_client_attestation`).
    private func rejected(_ response: HTTPResponse) async -> Error {
        let status = response.statusCode
        if status == 404 { return edgeClientUnknown(configuration.clientId) }
        if (300..<400).contains(status) {
            return OAuthError.configuration(.tokenRequestRejected(code: "(edge answered HTTP \(status) to /native/start; redirects are not followed)", description: nil))
        }
        if let failure = ServerFailure.error(for: response) { return failure }
        guard let error = TokenErrorPayload.parseStrict(response.body) else {
            return OAuthError.configuration(.tokenRequestRejected(code: "(no OAuth error in a HTTP \(status) response to /native/start)", description: nil))
        }
        // Edge never saw the attestation object this key was attested with: the next request attests a new key.
        if error.error == "invalid_client_attestation", error.errorDescription?.contains("has not been attested") == true {
            await attestation?.evidenceNotAccepted()
        }
        return OAuthError.configuration(.authorizationRejected(
            code: error.error.isEmpty ? "(no error code in a HTTP \(status) response to /native/start)" : error.error,
            description: error.errorDescription
        ))
    }
}

/// Keys of `PendingAuthorizationRequest.extensions` that the edge flow writes and `EdgeNativeTokenClient` reads.
package enum EdgeExtension {
    package static let blob = "blob"
    package static let tokenEndpoint = "token_endpoint"
    package static let revocationEndpoint = "revocation_endpoint"
}
