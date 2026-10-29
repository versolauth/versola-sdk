import Foundation
import OAuthCore
import os

/// The browser leg without a browser: opens the URI the SDK asks for through the virtual
/// network, follows the provider's redirects, submits the test user's forms through the
/// provider's `ProviderLogin`, and hands the SDK the redirect to the client. Cookies are kept
/// per name and sent to every request, `Secure` or not (Keycloak marks its session cookies
/// `Secure` over plain HTTP; a browser sends them to loopback).
final class HttpLoginBrowser: BrowserAuthorizationSession, Sendable {
    private let provider: Provider
    private let session = VirtualNetwork.session(record: false)
    private let state = OSAllocatedUnfairLock(initialState: State())

    struct State: Sendable {
        var opened: [URL] = []
        var dismissNext = false
        var cookies: [String: String] = [:]
        var onOpen: (@Sendable (URL) -> Void)?
    }

    init(provider: Provider) { self.provider = provider }

    var opened: [URL] { state.withLock { $0.opened } }
    func dismissNext() { state.withLock { $0.dismissNext = true } }
    func onOpen(_ hook: @escaping @Sendable (URL) -> Void) { state.withLock { $0.onOpen = hook } }

    private static let clientPrefixes = [Provider.redirectUri, Provider.postLogoutRedirectUri]

    func authorize(_ uri: URL, options: BrowserSessionOptions) async throws -> BrowserOutcome {
        let (dismiss, hook) = state.withLock { s -> (Bool, (@Sendable (URL) -> Void)?) in
            s.opened.append(uri)
            defer { s.dismissNext = false }
            return (s.dismissNext, s.onOpen)
        }
        hook?(uri)
        if dismiss { return .userCancelled }
        var (response, body) = try await send(URLRequest(url: uri))
        // Keycloak takes three hops, Hydra about ten; the bound is for a provider that loops.
        for _ in 0..<24 {
            let location = response.value(forHTTPHeaderField: "Location").flatMap { URL(string: $0, relativeTo: response.url)?.absoluteURL }
            switch response.statusCode {
            case 300..<400 where location != nil && Self.clientPrefixes.contains(where: { location!.absoluteString.hasPrefix($0) }):
                return .redirect(location!)
            case 300..<400 where location != nil:
                (response, body) = try await send(URLRequest(url: location!))
            case 200:
                guard let post = provider.login.step(page: body, pageURL: response.url!, username: provider.username, password: provider.password) else {
                    // Nothing to act on: an error page, or a confirmation the provider will not redirect from.
                    return .userCancelled
                }
                var request = URLRequest(url: post.url)
                request.httpMethod = "POST"
                request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
                request.httpBody = Data(post.fields.map { "\(Self.encode($0))=\(Self.encode($1))" }.joined(separator: "&").utf8)
                (response, body) = try await send(request)
            default:
                throw ConformanceFailure("the provider answered \(response.statusCode) at \(response.url?.absoluteString ?? "?"): \(body.prefix(300))")
            }
        }
        throw ConformanceFailure("the login conversation did not end in a redirect to the client")
    }

    func awaitPendingRedirect() async throws -> BrowserOutcome {
        throw ConformanceFailure("process death is scenario 12's, driven differently")
    }

    private func send(_ request: URLRequest) async throws -> (HTTPURLResponse, String) {
        var request = request
        let cookie = state.withLock { $0.cookies.map { "\($0.key)=\($0.value)" }.joined(separator: "; ") }
        if !cookie.isEmpty { request.setValue(cookie, forHTTPHeaderField: "Cookie") }
        let (data, response) = try await session.data(for: request)
        let http = response as! HTTPURLResponse
        for (name, value) in http.allHeaderFields where String(describing: name).lowercased() == "set-cookie" {
            // One or several cookies in one header value: name=value before the first ';'.
            for part in String(describing: value).components(separatedBy: ", ") {
                let pair = part.split(separator: ";", maxSplits: 1).first.map(String.init) ?? ""
                if let eq = pair.firstIndex(of: "=") {
                    let n = String(pair[..<eq]).trimmingCharacters(in: .whitespaces)
                    if !n.isEmpty, !n.contains(" ") { state.withLock { $0.cookies[n] = String(pair[pair.index(after: eq)...]) } }
                }
            }
        }
        return (http, String(decoding: data, as: UTF8.self))
    }

    private static func encode(_ value: String) -> String {
        value.addingPercentEncoding(withAllowedCharacters: CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")) ?? value
    }
}

struct ConformanceFailure: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}
