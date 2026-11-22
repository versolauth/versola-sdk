import Foundation
import OAuthCore

/// The two `htu` values the device signs for after login, kept so that a refresh or a revocation in
/// a later process (the common case) needs no `/native/start` it has no reason to make. Not
/// credential material: URLs edge hands to anyone who asks, so they are kept unencrypted and across
/// logout, like discovery metadata (`spec/versola-sdk-api.md` section 11).
package struct EdgeNativeEndpoints: Sendable, Equatable, Codable {
    package let tokenEndpoint: String
    package let revocationEndpoint: String

    package init(tokenEndpoint: String, revocationEndpoint: String) {
        self.tokenEndpoint = tokenEndpoint
        self.revocationEndpoint = revocationEndpoint
    }

    enum CodingKeys: String, CodingKey {
        case tokenEndpoint = "token_endpoint"
        case revocationEndpoint = "revocation_endpoint"
    }
}

package protocol EdgeEndpointsStore: Sendable {
    func load() async throws -> EdgeNativeEndpoints?
    func save(_ endpoints: EdgeNativeEndpoints) async throws
}

package actor InMemoryEdgeEndpointsStore: EdgeEndpointsStore {
    private var endpoints: EdgeNativeEndpoints?

    package init(_ endpoints: EdgeNativeEndpoints? = nil) { self.endpoints = endpoints }

    package func load() async throws -> EdgeNativeEndpoints? { endpoints }
    package func save(_ endpoints: EdgeNativeEndpoints) async throws { self.endpoints = endpoints }
}

/// A plain JSON file, replaced atomically; a file this version cannot read is deleted and read as
/// absent. Absent is not a fallback to anything: a refresh with no endpoints is
/// `reauthenticate(.credentialsInvalidated)`, since nothing here may be inferred (see
/// `EdgeNativeTokenClient`), so a damaged file costs one sign-in and never a guessed address.
package struct FileEdgeEndpointsStore: EdgeEndpointsStore {
    private let file: URL

    package init(file: URL) { self.file = file }

    package func load() async throws -> EdgeNativeEndpoints? {
        guard let data = try? Data(contentsOf: file) else { return nil }
        guard let endpoints = try? JSONDecoder().decode(EdgeNativeEndpoints.self, from: data) else {
            try? FileManager.default.removeItem(at: file)
            return nil
        }
        return endpoints
    }

    package func save(_ endpoints: EdgeNativeEndpoints) async throws {
        try FileManager.default.createDirectory(at: file.deletingLastPathComponent(), withIntermediateDirectories: true)
        try JSONEncoder().encode(endpoints).write(to: file, options: .atomic)
    }
}

/// Keys of `PendingAuthorizationRequest.extensions` that the edge flow writes and
/// `EdgeNativeTokenClient` reads.
package enum EdgeExtension {
    package static let blob = "blob"
    package static let tokenEndpoint = "token_endpoint"
    package static let revocationEndpoint = "revocation_endpoint"
}

/// Keys of `AuthorizationParameters.extra` that `EdgeAuthorizationStarter` forwards, by their wire
/// names. Nothing else of that map goes out, because edge forwards nothing else.
package enum EdgeParameter {
    package static let claims = "claims"
    package static let authorizationDetails = "authorization_details"
}

/// `{edge}/native/{endpoint}/{clientId}`, with the client id path-encoded. The scheme is not
/// judged here: the facade's configuration has already held the edge address to https (http on
/// loopback only), and the token client's own checks cover the addresses a response named.
package func edgeNativeUrl(_ edge: URL, endpoint: String, clientId: String) throws -> URL {
    var root = edge.absoluteString
    while root.hasSuffix("/") { root.removeLast() }
    // Everything outside the unreserved set, so that a client id with a `/` or a `?` stays one segment.
    let encoded = FormEncoding.percentEncode(clientId)
    guard let url = URL(string: "\(root)/native/\(endpoint)/\(encoded)"), url.scheme != nil, url.host != nil else {
        throw OAuthError.configuration(.invalidConfiguration(detail: "the edge URL is not usable as a base address"))
    }
    return url
}

/// An absolute `https` URL with a host, or `http` to a loopback host (`security.md`): the rule
/// every address the facade signs for or opens is held to.
package func isSecureEdgeEndpoint(_ endpoint: String) -> Bool {
    guard let components = URLComponents(string: endpoint), let scheme = components.scheme?.lowercased(),
          var host = components.host?.lowercased(), !host.isEmpty
    else { return false }
    if host.hasPrefix("[") && host.hasSuffix("]") { host = String(host.dropFirst().dropLast()) }
    if scheme == "https" { return true }
    return scheme == "http" && ["127.0.0.1", "localhost", "::1"].contains(host)
}
