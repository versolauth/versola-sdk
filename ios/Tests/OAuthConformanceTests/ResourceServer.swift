import Foundation
import OAuthCore

/// A protected resource on a virtual origin (scenario 24's second precondition): `/api` answers
/// 200 with the token's subject when the provider's UserInfo endpoint accepts the bearer token,
/// 401 with a `Bearer` challenge otherwise; `/redirect` answers a 302 to another origin
/// (scenario 32). The token is checked at the provider through the proxy, since a provider
/// that derives its issuer from the request issued it for the proxy's origin.
enum ResourceServer {
    static let origin = "http://localhost:18080"
    static let secondOrigin = "http://localhost:18081"

    /// Reads the provider's advertised UserInfo endpoint once (from its own discovery, not through
    /// the virtual network), re-rooted at the proxy, and installs the origin.
    static func install(_ network: VirtualNetwork, origin: String = ResourceServer.origin) async throws {
        let userinfo = try await userinfoEndpoint()
        network.resource(origin) { request in
            let token = request.value(forHTTPHeaderField: "Authorization").flatMap { $0.hasPrefix("Bearer ") ? String($0.dropFirst(7)) : nil }
            guard let token, let subject = await subjectOf(token, userinfo: userinfo) else {
                return VirtualNetwork.StubAnswer(status: 401, headers: ["WWW-Authenticate": "Bearer realm=\"resource\""])
            }
            if request.url?.path == "/redirect" {
                return VirtualNetwork.StubAnswer(status: 302, headers: ["Location": "https://elsewhere.example.com/landing"])
            }
            return VirtualNetwork.StubAnswer(status: 200, headers: ["Content-Type": "application/json"], body: Data("{\"sub\":\"\(subject)\"}".utf8))
        }
    }

    private static func userinfoEndpoint() async throws -> URL {
        let provider = VirtualNetwork.shared.provider!
        let (data, _) = try await URLSession.shared.data(from: URL(string: provider.issuer + "/.well-known/openid-configuration")!)
        guard let object = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any], let endpoint = object["userinfo_endpoint"] as? String else {
            throw ConformanceFailure("the provider advertises no userinfo_endpoint; the resource server cannot check tokens")
        }
        return URL(string: endpoint.replacingOccurrences(of: provider.origin, with: Provider.proxyOrigin))!
    }

    private static func subjectOf(_ token: String, userinfo: URL) async -> String? {
        var request = URLRequest(url: userinfo)
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        guard let (response, data) = try? await VirtualNetwork.shared.handle(request, record: false), response.statusCode == 200,
              let object = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else { return nil }
        return object["sub"] as? String
    }
}
