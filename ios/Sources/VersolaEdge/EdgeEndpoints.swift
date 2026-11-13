import Foundation
import OAuthCore

/// The two `htu` values the device signs for after login, kept so that a refresh or a revocation in
/// a later process -- the common case -- needs no `/native/start` it has no reason to make. Not
/// credential material: URLs edge hands to anyone who asks.
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

/// A plain JSON file, replaced atomically; a file this version cannot read is deleted and read as absent,
/// so a damaged one costs the discovery fallback and never a failed refresh.
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

/// `{edge}/native/{endpoint}/{clientId}`, with the client id path-encoded.
func edgeNativeUrl(_ base: URL, endpoint: String, clientId: String) throws -> URL {
    let unreserved = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
    var root = base.absoluteString
    while root.hasSuffix("/") { root.removeLast() }
    let encoded = clientId.addingPercentEncoding(withAllowedCharacters: unreserved) ?? clientId
    guard let url = URL(string: "\(root)/native/\(endpoint)/\(encoded)"), url.scheme == "https" else {
        throw OAuthError.configuration(.invalidConfiguration(detail: "the edge base URL must be an https URL"))
    }
    return url
}

/// Edge says 404 when it fronts no such client: the client is not `native`, not on a tenant assigned to
/// this edge, or edge has no `native` block. The most likely first-run mistake, so named as itself.
func edgeClientUnknown(_ clientId: String) -> OAuthError {
    .configuration(.invalidConfiguration(detail: "edge fronts no client '\(clientId)': check the client's kind, its tenant and edge's native configuration"))
}
