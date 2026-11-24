import Foundation
import OAuthCore

actor RecordingHTTP: HTTPClient {
    private(set) var requests: [HTTPRequest] = []
    private var queue: [HTTPResponse]

    init(_ responses: [HTTPResponse]) { queue = responses }

    func send(_ request: HTTPRequest) async throws -> HTTPResponse {
        requests.append(request)
        return queue.isEmpty ? HTTPResponse(statusCode: 500) : queue.removeFirst()
    }
}

func json(_ status: Int, _ body: String, headers: [String: String] = [:]) -> HTTPResponse {
    HTTPResponse(statusCode: status, headers: headers, body: Data(body.utf8))
}

/// Proofs whose payload carries a `jti` the test can predict: `jti-1`, `jti-2`, ...
actor ProofSource: DpopProofSource {
    private(set) var minted: [(url: URL, nonce: String?)] = []
    private var nonces: [String: String] = [:]

    func thumbprint() async throws -> String { "jkt" }

    func proof(method: String, url: URL, nonce: String?, accessToken: String?) async throws -> String {
        minted.append((url, nonce))
        let payload = Data(#"{"jti":"jti-\#(minted.count)"}"#.utf8).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        return "e30.\(payload).sig"
    }

    func observe(nonce: String, origin: String) async { nonces[origin] = nonce }
    func observe(serverDate: String?, age: String?, origin: String) async {}
    func nonce(for origin: String) async -> String? { nonces[origin] }
    func clearNonces() async { nonces.removeAll() }
}

/// Hands out `attestation_object` once, then assertions; counts refusals it was told about.
actor FakeEvidence: NativeStartAttestation {
    private(set) var asked: [(clientId: String, jkt: String, jti: String)] = []
    private(set) var notAccepted = 0
    private var attested = false

    func fields(clientId: String, jkt: String, jti: String) async throws -> [NativeStartField] {
        asked.append((clientId, jkt, jti))
        defer { attested = true }
        return attested
            ? NativeAttestation.fields(keyId: "key", assertion: Data([1, 2, 3]))
            : NativeAttestation.fields(keyId: "key", attestationObject: Data([0xfb, 0xff]))
    }

    func evidenceNotAccepted() async {
        notAccepted += 1
        attested = false
    }
}

func formFields(_ request: HTTPRequest) -> [String: String] {
    var fields: [String: String] = [:]
    for pair in String(data: request.body ?? Data(), encoding: .utf8)!.split(separator: "&") {
        let parts = pair.split(separator: "=", maxSplits: 1).map { String($0).removingPercentEncoding ?? "" }
        fields[parts[0]] = parts.count > 1 ? parts[1] : ""
    }
    return fields
}
