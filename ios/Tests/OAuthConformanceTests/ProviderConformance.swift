// A file added to or removed from this directory is also added to or removed from the RunnerTests
// target of the Flutter example (flutter/versola_oauth/example/ios/Runner.xcodeproj), which lists the
// driver's support files by name; the Scenario* files stay out of it. Android's example picks the
// directory up by itself. conformance/README.md, "Through the Flutter bridge".

import Foundation
import OAuthCore
import os
import XCTest
@testable import OAuthClient

/// What every generic-facade scenario starts from: the provider from the environment (or the
/// test skipped), the virtual network reset with the proxy and the resource origins, the HTTP
/// browser leg, and a client over in-memory stores. The scenario files are the assertions'
/// source; a test names the scenario it implements in its doc comment (`testing.md`).
class ProviderConformance: XCTestCase {
    var provider: Provider!
    var browser: HttpLoginBrowser!
    let network = VirtualNetwork.shared
    let logger = RecordingLogger()
    /// Where this test's DPoP key persists (scenario 33); one per test, so no key outlives its test.
    let dpopKeyStore = InMemoryDpopKeyStore()

    override func setUp() async throws {
        guard let staged = try Provider.fromEnvironment() else {
            throw XCTSkip("OAUTH_CONFORMANCE_ISSUER is not set: no provider to run against (conformance/README.md)")
        }
        provider = staged
        network.reset(provider: staged)
        try await ResourceServer.install(network)
        browser = HttpLoginBrowser(provider: staged)
        // The same issuer in every test: the per-process registry would refuse the next test's configuration.
        await OAuthClient.forgetAll()
    }

    override func tearDown() {
        guard provider != nil else { return }
        // Scenario 01's last assertion holds for every facade: no token, code or verifier at
        // any log level. Every secret the wire carried is checked against every line logged.
        let secrets = network.transcript.flatMap { entry -> [String] in
            var values: [String] = []
            if let json = entry.responseJSON {
                for key in ["access_token", "refresh_token", "id_token"] { if let value = json[key] as? String { values.append(value) } }
            }
            if let code = entry.field("code") { values.append(code) }
            if let verifier = entry.field("code_verifier") { values.append(verifier) }
            return values.filter { $0.count > 8 }
        }
        for line in logger.lines {
            for secret in secrets { XCTAssertFalse(line.contains(secret), "a secret reached the log: \(line)") }
        }
    }

    /// The issuer the SDK is configured with: the provider's issuer path at the proxy's origin.
    var proxyIssuer: String { Provider.proxyOrigin + provider.issuerPath }

    func configuration(
        clientId: String = Provider.clientId,
        endpoints: ProviderEndpoints? = nil,
        redirectUri: String = Provider.redirectUri,
        scopes: Set<String>? = nil,
        protectedOrigins: Set<String> = [ResourceServer.origin],
        pushedAuthorization: PushedAuthorization = .whenAdvertised,
        tokenBinding: TokenBinding = .bearer
    ) throws -> OAuthConfiguration {
        try OAuthConfiguration(
            issuer: endpoints == nil ? proxyIssuer : nil,
            endpoints: endpoints,
            clientId: clientId,
            redirectUri: redirectUri,
            postLogoutRedirectUri: Provider.postLogoutRedirectUri,
            scopes: scopes ?? provider.scopes,
            tokenBinding: tokenBinding,
            pushedAuthorization: pushedAuthorization,
            protectedOrigins: protectedOrigins,
            logger: logger,
            urlSession: VirtualNetwork.session(record: true)
        )
    }

    func client(_ configuration: OAuthConfiguration? = nil) async throws -> OAuthClient {
        // A Mac host has no Secure Enclave this process may use and its Keychain refuses an unsigned
        // one, and a simulator has no enclave at all: the key is the SDK's own `SecureEnclaveDpopKey`
        // told there is none, so the tier is software on every machine the driver runs on and
        // `requireHardware` has the same answer everywhere. The Secure Enclave tier is the device's.
        let store = dpopKeyStore
        return try await OAuthClient.create(
            configuration: try configuration ?? self.configuration(),
            browser: browser, credentialStore: InMemoryCredentialStore(), pendingStore: InMemoryPendingAuthorizationStore(),
            metadataCache: MemoryMetadataCache(), jwksCache: MemoryJwksCache(),
            dpopKey: { requireHardware, logger in
                SecureEnclaveDpopKey(store: store, requireHardware: requireHardware, logger: logger, secureEnclaveAvailable: false)
            }
        )
    }

    /// The one request the SDK made to `pathSuffix`, or fails naming how many there were.
    func theRequest(_ method: String, _ pathSuffix: String, file: StaticString = #filePath, line: UInt = #line) throws -> TranscriptEntry {
        let matching = network.matching(method, pathSuffix)
        XCTAssertEqual(matching.count, 1, "requests \(method) …\(pathSuffix): \(network.transcript.map { "\($0.method) \($0.url) -> \($0.status)" })", file: file, line: line)
        guard let entry = matching.first else { throw ConformanceFailure("no \(method) \(pathSuffix)") }
        return entry
    }

    func assertNoSecretOnTheWire(_ entry: TranscriptEntry, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertNil(entry.field("client_secret"), file: file, line: line)
        XCTAssertNil(entry.field("client_assertion"), file: file, line: line)
        XCTAssertFalse(entry.header("Authorization")?.hasPrefix("Basic") == true, file: file, line: line)
    }

    /// The `OAuthError` an operation surfaced, or fails when it succeeded or threw another error.
    func oauthError(file: StaticString = #filePath, line: UInt = #line, _ operation: () async throws -> Void) async -> OAuthError? {
        do {
            try await operation()
            XCTFail("the operation succeeded", file: file, line: line)
            return nil
        } catch let error as OAuthError {
            return error
        } catch {
            XCTFail("not an OAuthError: \(error)", file: file, line: line)
            return nil
        }
    }

    /// The path of a discovered endpoint at the proxy, as the transcript records it.
    func path(_ endpoint: String?) -> String { endpoint.map { $0.replacingOccurrences(of: Provider.proxyOrigin, with: "") } ?? "" }

    /// The query of a URL as a decoded map.
    func query(_ url: URL) -> [String: String] { AuthorizationResponseValidator.parseQuery(url) }
}

final class RecordingLogger: OAuthLogger, Sendable {
    private let store = OSAllocatedUnfairLock(initialState: [String]())
    var lines: [String] { store.withLock { $0 } }
    var warnings: [String] { lines.filter { $0.hasPrefix("warn: ") }.map { String($0.dropFirst(6)) } }
    func info(_ message: String) { store.withLock { $0.append("info: \(message)") } }
    func warn(_ message: String) { store.withLock { $0.append("warn: \(message)") } }
}
