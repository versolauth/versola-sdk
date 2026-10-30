import Flutter
import Foundation
import OAuthCore
import XCTest
@testable import OAuthClient
@testable import versola_oauth

/// What every bridge scenario starts from: the generic facade's conformance driver
/// (`ProviderConformance`: the provider from the environment or the test skipped, the virtual
/// network, the HTTP browser leg, the transcript on the SDK's session), with the plugin's
/// `VersolaOAuthPlugin` registered on a `FakeMessenger` and every operation under test sent
/// through its Pigeon host API by a `DartSide`, as a Flutter app's Dart code would.
///
/// **How the driver's wiring reaches the plugin.** The browser leg and the stores are replaced
/// through the SDK's package-level constructor, which the plugin must not call (`flutter.md`: the
/// plugin uses the public API only). `bridge(...)` therefore builds the native client first, with
/// the driver's wiring, and then asks the plugin to `create` the same configuration through the
/// host API. The SDK keeps one instance per configuration per process and returns the first one
/// to a second `create` with the same configuration (its fingerprint: everything but the URL
/// session and the logger), so the plugin ends up holding the driver's instance. A bridge that
/// converted any field differently from the native configuration the test built would not find
/// that instance: `create` would be refused for a different configuration, and the test fails at
/// its first line.
///
/// What the bridge does not carry stays on the native instance, used only to *observe* (the
/// discovery document, the configuration's retry policy): `metadata()` and the authenticated
/// session are not Flutter API (`spec/oauth-sdk-api.md` section 10: Flutter has `accessToken()`
/// only), so a scenario's authenticated calls are made here the way a Flutter app makes them,
/// with the token the bridge hands over.
class BridgeConformance: ProviderConformance {
    let messenger = FakeMessenger()
    private var darts: [DartSide] = []

    /// The app's own HTTP session: what `dio` or `http` is in a Flutter app. Not the SDK's, so not in the transcript.
    let app = VirtualNetwork.session(record: false)

    override func setUp() async throws {
        try await super.setUp()
        VersolaOAuthPlugin.register(with: FakeRegistrar(messenger))
    }

    override func tearDown() {
        if provider != nil {
            OAuthHostApiSetup.setUp(binaryMessenger: messenger, api: nil)
            // Nothing credential-shaped crossed the bridge (flutter.md, "What crosses the bridge"):
            // no refresh token, no raw ID token, no authorization code, no PKCE verifier, no `state` in any
            // reply or event, and the access token only in the reply of accessToken().
            var secrets: [String] = []
            for entry in network.transcript {
                if let json = entry.responseJSON {
                    for key in ["refresh_token", "id_token", "access_token"] { if let value = json[key] as? String { secrets.append(value) } }
                }
                if let code = entry.field("code") { secrets.append(code) }
                if let verifier = entry.field("code_verifier") { secrets.append(verifier) }
                if let state = entry.field("state") { secrets.append(state) }
            }
            for value in darts.flatMap(\.received) {
                for secret in secrets where secret.count > 8 { XCTAssertFalse(value.contains(secret), "a credential crossed the bridge: \(value)") }
            }
        }
        super.tearDown()
    }

    /// A native client and the Dart side that created it through the host API.
    struct Bridge {
        let native: OAuthClient
        let dart: DartSide
    }

    /// Wires the native client of one configuration the way the native driver does, then creates
    /// it through the host API exactly as Dart's `OAuth.create` would (the handle is what
    /// native answers with, not derived here). The parameters are those
    /// of `configuration(...)`; the message is built from the same values.
    func bridge(
        clientId: String = Provider.clientId,
        endpoints: ProviderEndpoints? = nil,
        redirectUri: String = Provider.redirectUri,
        scopes: Set<String>? = nil,
        protectedOrigins: Set<String> = [ResourceServer.origin],
        pushedAuthorization: PushedAuthorization = .whenAdvertised,
        tokenBinding: TokenBinding = .bearer
    ) async throws -> Bridge {
        let native = try await client(
            configuration(clientId: clientId, endpoints: endpoints, redirectUri: redirectUri, scopes: scopes, protectedOrigins: protectedOrigins, pushedAuthorization: pushedAuthorization, tokenBinding: tokenBinding)
        )
        let dart = dart()
        let created = try await dart.create(message(clientId: clientId, endpoints: endpoints, redirectUri: redirectUri, scopes: scopes, protectedOrigins: protectedOrigins, pushedAuthorization: pushedAuthorization, tokenBinding: tokenBinding))
        if let failure = created as? CreateFailure {
            throw BridgeFailure("expected CreateOk, got \(failure.error.category)/\(failure.error.kind): \(failure.error.message)")
        }
        return Bridge(native: native, dart: dart)
    }

    /// A Dart side with no client yet: what `create` is sent through, a failing one included.
    func dart() -> DartSide {
        let dart = DartSide(messenger)
        darts.append(dart)
        return dart
    }

    /// The configuration Dart's `toMessage` produces for the values `bridge(...)` takes; every other field at its documented default.
    func message(
        clientId: String = Provider.clientId,
        endpoints: ProviderEndpoints? = nil,
        redirectUri: String = Provider.redirectUri,
        scopes: Set<String>? = nil,
        protectedOrigins: Set<String> = [ResourceServer.origin],
        pushedAuthorization: PushedAuthorization = .whenAdvertised,
        issuer: String?? = nil,
        tokenBinding: TokenBinding = .bearer
    ) -> ConfigurationMessage {
        ConfigurationMessage(
            issuer: issuer ?? (endpoints == nil ? proxyIssuer : nil),
            endpoints: endpoints.map {
                EndpointsMessage(
                    issuer: $0.issuer, authorizationEndpoint: $0.authorizationEndpoint, tokenEndpoint: $0.tokenEndpoint, jwksUri: $0.jwksUri,
                    userinfoEndpoint: $0.userinfoEndpoint, revocationEndpoint: $0.revocationEndpoint, endSessionEndpoint: $0.endSessionEndpoint,
                    pushedAuthorizationRequestEndpoint: $0.pushedAuthorizationRequestEndpoint,
                    idTokenSigningAlgValuesSupported: $0.idTokenSigningAlgValuesSupported
                )
            },
            clientId: clientId,
            redirectUri: redirectUri,
            postLogoutRedirectUri: Provider.postLogoutRedirectUri,
            scopes: Array(scopes ?? provider.scopes),
            tokenBinding: {
                switch tokenBinding {
                case .bearer: return .bearer
                case .dpop(let required): return required ? .dpopRequireHardware : .dpop
                }
            }(),
            pushedAuthorization: {
                switch pushedAuthorization {
                case .never: return .never
                case .whenAdvertised: return .whenAdvertised
                case .required: return .required
                }
            }(),
            protectedOrigins: Array(protectedOrigins),
            endSessionEndpoint: nil,
            unlockPolicy: .none,
            clockSkewToleranceSeconds: 60,
            retryPolicy: nil
        )
    }

    // MARK: the typed answers, as a Flutter app reads them

    /// The error a `create` answered with, or fails when it succeeded.
    func failure(_ result: CreateResult) throws -> ErrorMessage {
        guard let failure = result as? CreateFailure else { throw BridgeFailure("expected CreateFailure, the client was created") }
        return failure.error
    }

    func ok(_ result: VoidResult, file: StaticString = #filePath, line: UInt = #line) throws {
        if let failure = result as? VoidFailure {
            throw BridgeFailure("expected VoidOk, got \(failure.error.category)/\(failure.error.kind): \(failure.error.message)")
        }
    }

    /// The error a Void operation answered with, or fails when it succeeded.
    func failure(_ result: VoidResult) throws -> ErrorMessage {
        guard let failure = result as? VoidFailure else { throw BridgeFailure("expected VoidFailure, the operation succeeded") }
        return failure.error
    }

    func token(_ result: AccessTokenResult) throws -> AccessTokenMessage {
        if let ok = result as? AccessTokenOk { return ok.token }
        let error = (result as? AccessTokenFailure)?.error
        throw BridgeFailure("expected AccessTokenOk, got \(String(describing: error?.category))/\(error?.kind ?? "?")")
    }

    func failure(_ result: AccessTokenResult) throws -> ErrorMessage {
        guard let failure = result as? AccessTokenFailure else { throw BridgeFailure("expected AccessTokenFailure, a token was handed over") }
        return failure.error
    }

    func failure(_ result: UserInfoResult) throws -> ErrorMessage {
        guard let failure = result as? UserInfoFailure else { throw BridgeFailure("expected UserInfoFailure, the operation succeeded") }
        return failure.error
    }

    func subject(_ result: UserInfoResult) throws -> String {
        if let ok = result as? UserInfoOk { return ok.userInfo.subject }
        let error = (result as? UserInfoFailure)?.error
        throw BridgeFailure("expected UserInfoOk, got \(String(describing: error?.category))/\(error?.kind ?? "?")")
    }

    /// `error` is the category and case the native error `spec/errors.md` names, as the wire spells them.
    func assertError(_ error: ErrorMessage, _ category: ErrorCategoryMessage, _ kind: String, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertTrue(error.category == category && error.kind == kind, "\(error.category)/\(error.kind): \(error.message)", file: file, line: line)
    }

    /// A Flutter app's authenticated call: the token the bridge handed over, attached by the app.
    func appCall(_ token: AccessTokenMessage, _ url: String) async throws -> (Data, HTTPURLResponse) {
        var request = URLRequest(url: URL(string: url)!)
        request.setValue("\(token.tokenType) \(token.value)", forHTTPHeaderField: "Authorization")
        let (data, response) = try await app.data(for: request)
        return (data, response as! HTTPURLResponse)
    }

    func assertTokenIsUsableAtTheResource(_ token: AccessTokenMessage, subject: String, file: StaticString = #filePath, line: UInt = #line) async throws {
        XCTAssertEqual(token.tokenType, "Bearer", file: file, line: line)
        let (data, response) = try await appCall(token, ResourceServer.origin + "/api")
        XCTAssertEqual(response.statusCode, 200, String(decoding: data, as: UTF8.self), file: file, line: line)
        XCTAssertTrue(String(decoding: data, as: UTF8.self).contains(subject), file: file, line: line)
    }

    /// Waits until `condition` holds; bounded, never a fixed delay.
    func until(_ what: String, timeout: TimeInterval = 30, _ condition: @escaping () -> Bool) async throws {
        let deadline = Date().addingTimeInterval(timeout)
        while !condition() {
            if Date() > deadline { throw BridgeFailure("timed out after \(timeout) s waiting until \(what)") }
            try await Task.sleep(nanoseconds: 5_000_000)
        }
    }
}
