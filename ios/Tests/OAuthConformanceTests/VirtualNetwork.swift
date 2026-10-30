import Foundation
import OAuthCore
import os

/// What the proxy records of each exchange, as it went on the wire. The scenarios' assertions
/// read it. Mirrors the Android driver's `Transcript.Entry`.
struct TranscriptEntry: Sendable {
    let method: String
    let url: String
    let headers: [String: String]
    let body: String?
    let status: Int
    let responseHeaders: [String: String]
    let responseBody: String?
    let at: Date

    var path: String { URL(string: url)?.path ?? "" }
    func header(_ name: String) -> String? { headers.first { $0.key.caseInsensitiveCompare(name) == .orderedSame }?.value }
    func responseHeader(_ name: String) -> String? { responseHeaders.first { $0.key.caseInsensitiveCompare(name) == .orderedSame }?.value }
    /// `application/x-www-form-urlencoded` fields, decoded (repeated names keep every value).
    var form: [String: [String]] {
        var fields: [String: [String]] = [:]
        for pair in (body ?? "").split(separator: "&") {
            let parts = pair.split(separator: "=", maxSplits: 1).map { String($0).replacingOccurrences(of: "+", with: " ").removingPercentEncoding ?? "" }
            fields[parts[0], default: []].append(parts.count > 1 ? parts[1] : "")
        }
        return fields
    }
    func field(_ name: String) -> String? { form[name]?.first }
    var responseJSON: [String: Any]? { responseBody.flatMap { (try? JSONSerialization.jsonObject(with: Data($0.utf8))) as? [String: Any] } }
}

/// The driver's network, in process: a `URLProtocol` on every session the fixture hands out.
/// The proxy origin forwards to the real provider with the proxy's own `Host`, so a provider
/// that builds its URLs from the request (Keycloak) announces the proxy as itself, and one
/// that builds them from configuration (Hydra) was told this origin in advance. It is also the
/// fault-injection seam: canned answers, body rewrites and added headers per path, and the
/// resource origins the authenticated client is pointed at.
final class VirtualNetwork: Sendable {
    struct State: Sendable {
        var provider: Provider?
        var intercept: (@Sendable (URLRequest) -> StubAnswer?)?
        var rewrites: [(String, @Sendable (String) async -> String)] = []
        var addedHeaders: [(String, [String: String])] = []
        var requestRewrites: [(String, @Sendable (URLRequest) -> URLRequest)] = []
        var resources: [String: @Sendable (URLRequest) async -> StubAnswer] = [:]
        var requests: [URLRequest] = []
        var transcript: [TranscriptEntry] = []
    }

    struct StubAnswer: Sendable {
        var status: Int
        var headers: [String: String] = [:]
        var body: Data = Data()
    }

    static let shared = VirtualNetwork()
    private let state = OSAllocatedUnfairLock(initialState: State())
    /// The forwarding session: no interception, no cookies, no redirects followed, no caching.
    private let upstream: URLSession = {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpShouldSetCookies = false
        configuration.httpCookieAcceptPolicy = .never
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        return URLSession(configuration: configuration, delegate: NoRedirects(), delegateQueue: nil)
    }()

    private final class NoRedirects: NSObject, URLSessionTaskDelegate, Sendable {
        func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
            completionHandler(nil)
        }
    }

    func reset(provider: Provider) {
        state.withLock { $0 = State(provider: provider) }
    }

    func intercept(_ handler: (@Sendable (URLRequest) -> StubAnswer?)?) { state.withLock { $0.intercept = handler } }
    /// The hooks are `async`: they run inside `handle`, on the cooperative pool, and may await
    /// the client's actors; a semaphore there would park the thread the awaited work needs.
    func rewrite(_ pathSuffix: String, _ body: @escaping @Sendable (String) async -> String) { state.withLock { $0.rewrites.append((pathSuffix, body)) } }
    func rewriteJSON(_ pathSuffix: String, _ body: @escaping @Sendable ([String: Any]) -> [String: Any]) {
        rewrite(pathSuffix) { raw in
            guard let object = (try? JSONSerialization.jsonObject(with: Data(raw.utf8))) as? [String: Any],
                  let data = try? JSONSerialization.data(withJSONObject: body(object)) else { return raw }
            return String(decoding: data, as: UTF8.self)
        }
    }
    func addHeaders(_ pathSuffix: String, _ headers: [String: String]) { state.withLock { $0.addedHeaders.append((pathSuffix, headers)) } }
    /// Rewrites the request the proxy forwards to the provider for a path suffix (what the SDK sent is still
    /// what the transcript records): a thief's token request, say, with a proof that is not the SDK's.
    func rewriteRequest(_ pathSuffix: String, _ transform: @escaping @Sendable (URLRequest) -> URLRequest) { state.withLock { $0.requestRewrites.append((pathSuffix, transform)) } }
    func clearRewrites() { state.withLock { $0.rewrites = []; $0.addedHeaders = []; $0.requestRewrites = []; $0.intercept = nil } }
    func resource(_ origin: String, _ handler: @escaping @Sendable (URLRequest) async -> StubAnswer) { state.withLock { $0.resources[origin] = handler } }

    var requests: [URLRequest] { state.withLock { $0.requests } }
    var transcript: [TranscriptEntry] { state.withLock { $0.transcript } }
    func matching(_ method: String, _ pathSuffix: String) -> [TranscriptEntry] {
        transcript.filter { $0.method == method && $0.path.hasSuffix(pathSuffix) }
    }
    var provider: Provider? { state.withLock { $0.provider } }

    /// A session whose requests go through the virtual network; `record` for the SDK's own.
    static func session(record: Bool) -> URLSession {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [record ? RecordingProtocol.self : BrowserProtocol.self]
        configuration.httpShouldSetCookies = false
        configuration.httpCookieAcceptPolicy = .never
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        return URLSession(configuration: configuration)
    }

    static func origin(of url: URL) -> String {
        var origin = "\(url.scheme ?? "")://\(url.host ?? "")"
        if let port = url.port { origin += ":\(port)" }
        return origin
    }

    /// Answers one request: a resource, a canned answer, or the provider through the proxy.
    func handle(_ request: URLRequest, record: Bool) async throws -> (HTTPURLResponse, Data) {
        guard let url = request.url else { throw URLError(.badURL) }
        let snapshot = state.withLock { $0 }
        let origin = Self.origin(of: url)
        if let handler = snapshot.resources[origin] {
            let answer = await handler(request)
            return finish(request, answer, record: record)
        }
        guard let provider = snapshot.provider else { return finish(request, StubAnswer(status: 599), record: record) }
        if origin != Provider.proxyOrigin {
            // The browser leg reaches a provider's own helpers directly (Hydra's consent app on
            // localhost:3000): loopback passes through as is. Anything else is unreachable on
            // purpose: the driver's world is the provider and its resources, and a request
            // elsewhere is a finding, not a network trip.
            guard url.host == "localhost" || url.host == "127.0.0.1" else { return finish(request, StubAnswer(status: 599), record: record) }
            var passthrough = request
            passthrough.httpBody = request.httpBody ?? request.httpBodyStream.map(Self.drain)
            let (data, response) = try await upstream.data(for: passthrough)
            let http = response as! HTTPURLResponse
            var headers: [String: String] = [:]
            for (name, value) in http.allHeaderFields { headers[String(describing: name)] = String(describing: value) }
            return finish(request, StubAnswer(status: http.statusCode, headers: headers, body: data), record: record)
        }
        state.withLock { $0.requests.append(request) }
        if let intercept = snapshot.intercept, let answer = intercept(request) {
            return finish(request, answer, record: record)
        }
        // Forward with the proxy's own Host; the length and encoding headers are the
        // session's to set, and without a client Accept-Encoding it decodes gzip itself.
        var forwarded = URLRequest(url: URL(string: provider.origin + url.path + (url.query.map { "?\($0)" } ?? ""))!)
        forwarded.httpMethod = request.httpMethod
        forwarded.httpBody = request.httpBody ?? request.httpBodyStream.map(Self.drain)
        for (name, value) in request.allHTTPHeaderFields ?? [:] where !["host", "content-length", "transfer-encoding", "connection", "accept-encoding"].contains(name.lowercased()) {
            forwarded.setValue(value, forHTTPHeaderField: name)
        }
        forwarded.setValue("localhost:14444", forHTTPHeaderField: "Host")
        for (suffix, transform) in snapshot.requestRewrites where url.path.hasSuffix(suffix) { forwarded = transform(forwarded) }
        let (data, response) = try await upstream.data(for: forwarded)
        let http = response as! HTTPURLResponse
        var text = String(decoding: data, as: UTF8.self)
        for (suffix, rewrite) in snapshot.rewrites where url.path.hasSuffix(suffix) { text = await rewrite(text) }
        var headers: [String: String] = [:]
        for (name, value) in http.allHeaderFields {
            let key = String(describing: name)
            if !["content-length", "content-encoding", "transfer-encoding", "connection"].contains(key.lowercased()) { headers[key] = String(describing: value) }
        }
        for (suffix, extra) in snapshot.addedHeaders where url.path.hasSuffix(suffix) { headers.merge(extra) { $1 } }
        return finish(request, StubAnswer(status: http.statusCode, headers: headers, body: Data(text.utf8)), record: record)
    }

    private func finish(_ request: URLRequest, _ answer: StubAnswer, record: Bool) -> (HTTPURLResponse, Data) {
        if record {
            let body = request.httpBody ?? request.httpBodyStream.map(Self.drain)
            let entry = TranscriptEntry(
                method: request.httpMethod ?? "GET", url: request.url!.absoluteString, headers: request.allHTTPHeaderFields ?? [:],
                body: body.map { String(decoding: $0, as: UTF8.self) }, status: answer.status, responseHeaders: answer.headers,
                responseBody: String(decoding: answer.body, as: UTF8.self), at: Date()
            )
            state.withLock { $0.transcript.append(entry) }
        }
        let response = HTTPURLResponse(url: request.url!, statusCode: answer.status, httpVersion: "HTTP/1.1", headerFields: answer.headers)!
        return (response, answer.body)
    }

    static func drain(_ stream: InputStream) -> Data {
        stream.open()
        defer { stream.close() }
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 8192)
        while stream.hasBytesAvailable {
            let read = stream.read(&buffer, maxLength: buffer.count)
            if read <= 0 { break }
            data.append(buffer, count: read)
        }
        return data
    }
}

/// The protocol class on the SDK's sessions: every exchange goes into the transcript. The two
/// subclasses hold no state of their own; the instance crosses into the async world inside
/// `ProtocolBox`, which says why that is safe.
final class RecordingProtocol: URLProtocol {
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() { VirtualProtocols.load(self, record: true) }
    override func stopLoading() {}
}

/// The protocol class on the browser leg's session: the same network, nothing recorded.
final class BrowserProtocol: URLProtocol {
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() { VirtualProtocols.load(self, record: false) }
    override func stopLoading() {}
}

enum VirtualProtocols {
    static func load(_ protocol: URLProtocol, record: Bool) {
        let request = `protocol`.request
        let box = ProtocolBox(`protocol`)
        Task {
            do {
                let (response, data) = try await VirtualNetwork.shared.handle(request, record: record)
                box.finish(response: response, data: data)
            } catch {
                box.fail(error)
            }
        }
    }

    /// `URLProtocol` is not Sendable; the client callbacks are thread-safe by contract.
    private struct ProtocolBox: @unchecked Sendable {
        let value: URLProtocol
        init(_ value: URLProtocol) { self.value = value }
        func finish(response: HTTPURLResponse, data: Data) {
            value.client?.urlProtocol(value, didReceive: response, cacheStoragePolicy: .notAllowed)
            value.client?.urlProtocol(value, didLoad: data)
            value.client?.urlProtocolDidFinishLoading(value)
        }
        func fail(_ error: Error) { value.client?.urlProtocol(value, didFailWithError: error) }
    }
}
