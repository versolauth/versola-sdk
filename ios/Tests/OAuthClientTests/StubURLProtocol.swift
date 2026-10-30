import Foundation
import os

/// What a stubbed request answers.
enum StubOutcome: Sendable {
    case response(status: Int, headers: [String: String] = [:], body: Data = Data())
    /// The 3xx a real server would send, offered to the session's redirect machinery: a session
    /// that follows redirects will issue a second request to `location`.
    case redirect(status: Int = 302, location: String)
    case failure(URLError.Code)
    /// Accepts the request and never answers: a provider that stopped responding.
    case hang
}

/// A `URLProtocol` that answers from a closure, on an ephemeral session, so no test touches a
/// network (`testing.md`). One handler at a time: XCTest runs a class's tests serially, and
/// every test installs its own and removes it in `tearDown`.
final class StubURLProtocol: URLProtocol {
    private struct State: Sendable {
        var handler: (@Sendable (URLRequest) -> StubOutcome)?
        var requests: [URLRequest] = []
    }

    private static let state = OSAllocatedUnfairLock(initialState: State())

    static func install(_ handler: @escaping @Sendable (URLRequest) -> StubOutcome) {
        state.withLock {
            $0.handler = handler
            $0.requests = []
        }
    }

    static func reset() {
        state.withLock {
            $0.handler = nil
            $0.requests = []
        }
    }

    /// Every request that reached the "network", in order.
    static var requests: [URLRequest] { state.withLock { $0.requests } }

    static func session() -> URLSession {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [StubURLProtocol.self]
        return URLSession(configuration: configuration)
    }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        let request = self.request
        let handler = Self.state.withLock { state -> (@Sendable (URLRequest) -> StubOutcome)? in
            state.requests.append(request)
            return state.handler
        }
        guard let url = request.url, let handler else {
            client?.urlProtocol(self, didFailWithError: URLError(.unsupportedURL))
            return
        }
        switch handler(request) {
        case .response(let status, let headers, let body):
            let response = HTTPURLResponse(url: url, statusCode: status, httpVersion: "HTTP/1.1", headerFields: headers)!
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: body)
            client?.urlProtocolDidFinishLoading(self)
        case .redirect(let status, let location):
            let response = HTTPURLResponse(url: url, statusCode: status, httpVersion: "HTTP/1.1", headerFields: ["Location": location])!
            client?.urlProtocol(self, wasRedirectedTo: URLRequest(url: URL(string: location)!), redirectResponse: response)
            // Reached only when the session declined to follow (a followed redirect stops this
            // protocol first): the 3xx is then the answer, as it is from a real server.
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocolDidFinishLoading(self)
        case .failure(let code):
            client?.urlProtocol(self, didFailWithError: URLError(code))
        case .hang:
            break
        }
    }

    override func stopLoading() {}
}

extension URLRequest {
    /// The body as the code under test set it: `URLProtocol` sees it as a stream.
    var bodyData: Data? {
        if let httpBody { return httpBody }
        guard let stream = httpBodyStream else { return nil }
        stream.open()
        defer { stream.close() }
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 1024)
        while stream.hasBytesAvailable {
            let count = stream.read(&buffer, maxLength: buffer.count)
            if count <= 0 { break }
            data.append(buffer, count: count)
        }
        return data
    }
}
