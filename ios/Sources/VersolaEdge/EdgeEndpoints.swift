import Foundation
import OAuthCore
import Security

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

/// A plain JSON file, replaced atomically. Absent and undecodable are the same answer, nil: a file
/// this version cannot parse is deleted, and absent is not a fallback to anything (a refresh with no
/// endpoints is `reauthenticate(.credentialsInvalidated)`, since nothing here may be inferred, see
/// `EdgeNativeTokenClient`), so a damaged file costs one sign-in and never a guessed address.
///
/// Nothing else is nil. A file that exists and cannot be read right now (the store out of reach, a
/// fault of the volume) is an error, typed by ``edgeStoreFailure(_:)``: read as "no endpoints" it would
/// end in `credentialsInvalidated` and a wiped session, for a grant that is perfectly good.
package struct FileEdgeEndpointsStore: EdgeEndpointsStore {
    private let file: URL

    package init(file: URL) { self.file = file }

    package func load() async throws -> EdgeNativeEndpoints? {
        let data: Data
        do {
            data = try Data(contentsOf: file)
        } catch {
            if isAbsentFile(error) { return nil }
            throw edgeStoreFailure(error)
        }
        guard let endpoints = try? JSONDecoder().decode(EdgeNativeEndpoints.self, from: data) else {
            try? FileManager.default.removeItem(at: file)
            return nil
        }
        return endpoints
    }

    package func save(_ endpoints: EdgeNativeEndpoints) async throws {
        do {
            try FileManager.default.createDirectory(at: file.deletingLastPathComponent(), withIntermediateDirectories: true)
            try JSONEncoder().encode(endpoints).write(to: file, options: .atomic)
        } catch {
            throw edgeStoreFailure(error)
        }
    }
}

/// Whether a read failed because there is no file: the one failure that means "nothing stored".
package func isAbsentFile(_ error: Error) -> Bool {
    let bridged = error as NSError
    if bridged.domain == NSCocoaErrorDomain, [NSFileNoSuchFileError, NSFileReadNoSuchFileError].contains(bridged.code) { return true }
    if bridged.domain == NSPOSIXErrorDomain, bridged.code == Int(ENOENT) { return true }
    if let underlying = bridged.userInfo[NSUnderlyingErrorKey] as? Error { return isAbsentFile(underlying) }
    return false
}

/// How a failure of the endpoints store is typed, the way the credential stores type theirs
/// (`KeychainFailure`, `KeychainItem.error(for:)` in `OAuthClient`): a store that is out of reach for
/// now (`errSecInteractionNotAllowed`, `errSecNotAvailable`, `errSecAuthFailed`: the device is locked or
/// has not been unlocked since boot) is `recoverable(.unlockRequired)`, the grant intact; any other is
/// a fault no retry changes, `configuration(.invalidConfiguration)`. An `OAuthError` already typed
/// passes through. The detail names the error's domain and code and nothing of the file's content, and
/// never the path.
package func edgeStoreFailure(_ error: Error) -> OAuthError {
    if let typed = error as? OAuthError { return typed }
    let bridged = error as NSError
    if bridged.domain == NSOSStatusErrorDomain {
        let status = OSStatus(truncatingIfNeeded: bridged.code)
        if status == errSecInteractionNotAllowed || status == errSecNotAvailable || status == errSecAuthFailed {
            return .recoverable(.unlockRequired)
        }
    }
    if let underlying = bridged.userInfo[NSUnderlyingErrorKey] as? NSError, underlying.domain == NSOSStatusErrorDomain {
        return edgeStoreFailure(underlying)
    }
    return .configuration(.invalidConfiguration(detail: "the edge endpoints store failed (\(bridged.domain) \(bridged.code))"))
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
