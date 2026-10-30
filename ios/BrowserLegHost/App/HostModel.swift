import AuthenticationServices
import OAuthClient
import SwiftUI
import UIKit

/// Owns the client and the on-screen log. The log never holds a token, a code or a `state`;
/// each outcome the SDK reports is one line: `state: <state>`, `login: ok` or
/// `login: failed <error>`, `claims: ...`, `accessToken: ...`, `userinfo: ...`, `refresh: ...`,
/// `logout: ...`, `resume: ...`.
@MainActor
@Observable
final class HostModel {
    private(set) var log = ""

    private var client: OAuthClient?
    private var started = false

    func append(_ line: String) {
        log += line + "\n"
    }

    /// Creates the client once per process. The issuer comes from the launch environment
    /// (`ISSUER`) and is kept in the defaults, because a launch by URL (a cold start through the
    /// redirect) carries no environment. It is the one the provider's discovery announces.
    func start() async {
        guard !started else { return }
        started = true
        append("process: started")
        let defaults = UserDefaults.standard
        if let issuer = ProcessInfo.processInfo.environment["ISSUER"] { defaults.set(issuer, forKey: "issuer") }
        guard let issuer = defaults.string(forKey: "issuer") else {
            append("configuration refused: no issuer; launch with the ISSUER environment variable")
            return
        }
        do {
            let configuration = try OAuthConfiguration(
                issuer: issuer,
                clientId: "conformance-device",
                redirectUri: "com.example.versola.devicetier://app/oauth",
                postLogoutRedirectUri: "com.example.versola.devicetier://app/signed-out",
                scopes: ["openid", "profile"],
                protectedOrigins: [origin(of: issuer)],
                logger: LogLines { [weak self] line in Task { @MainActor in self?.append(line) } }
            )
            let created = try await OAuthClient.create(configuration: configuration) {
                UIApplication.shared.connectedScenes
                    .compactMap { $0 as? UIWindowScene }
                    .flatMap(\.windows)
                    .first(where: \.isKeyWindow) ?? ASPresentationAnchor()
            }
            client = created
            // `-resetState YES` (the UI tests' first launch): a clean slate through the public
            // API, since a local sign-out wipes the stored grant and the pending request alike.
            if UserDefaults.standard.bool(forKey: "resetState") {
                _ = await created.logout(LogoutOptions(endSession: false, revoke: false))
            }
            if let url = earlyURL {
                earlyURL = nil
                await handle(url)
            }
            for await state in await created.sessionStates() {
                append("state: \(state.rawValue)")
                // `create` already finishes a restored `authorizing` on its own; this host calls
                // `OAuthClient.resumePendingAuthorization` once only to await the outcome and
                // log it (`resume: ...`), which the UI tests read. It joins the resume `create`
                // started, so the code is not exchanged twice.
                if state == .authorizing, !resuming, !loginInFlight {
                    resuming = true
                    Task { await resume(created) }
                }
            }
        } catch {
            append("configuration refused: \(describe(error))")
        }
    }

    private var earlyURL: URL?
    private var resuming = false
    private var loginInFlight = false

    private func resume(_ client: OAuthClient) async {
        defer { resuming = false }
        do {
            try await client.resumePendingAuthorization()
            append("resume: ok")
        } catch {
            append("resume: failed \(describe(error))")
        }
    }

    func login(ephemeral: Bool) async {
        guard let client else { return }
        loginInFlight = true
        defer { loginInFlight = false }
        do {
            try await client.login(LoginOptions(ephemeralBrowser: ephemeral))
            append("login: ok")
            let claims = await client.claims
            append("claims: preferred_username=\(claims?.all["preferred_username"] ?? "nil") issuer=\(claims?.issuer ?? "nil")")
        } catch {
            append("login: failed \(describe(error))")
        }
    }

    func token() async {
        guard let client else { return }
        do {
            let token = try await client.accessToken()
            append("accessToken: present=\(!token.value.isEmpty) type=\(token.tokenType)")
            // Spent on the provider's own UserInfo endpoint, which only answers for a token it
            // issued: that is the proof the token works.
            let info = try await client.userInfo()
            append("userinfo: preferred_username=\(info.claims["preferred_username"] ?? "nil")")
        } catch {
            append("accessToken: failed \(describe(error))")
        }
    }

    func refresh() async {
        guard let client else { return }
        do {
            try await client.refresh()
            append("refresh: ok")
        } catch {
            append("refresh: failed \(describe(error))")
        }
    }

    func logout() async {
        guard let client else { return }
        let outcome = await client.logout()
        append("logout: sessionEnded=\(outcome.sessionEnded) tokenRevoked=\(outcome.tokenRevoked)")
    }

    /// A URL the system opened the app with. One that arrives before the client exists (a cold
    /// start by URL runs this before `start()` has finished) is kept and handed over then.
    func handle(_ url: URL) async {
        append("open: url \(url.scheme ?? "")://\(url.host ?? "")\(url.path)")
        guard let client else {
            earlyURL = url
            return
        }
        let taken = await client.handleRedirect(url)
        append("redirect: \(taken ? "taken by the SDK" : "not the SDK's")")
    }

    /// The category and its cause, nothing an error's message might quote.
    private func describe(_ error: any Error) -> String {
        guard let error = error as? OAuthError else { return "\(type(of: error))" }
        switch error {
        case .recoverable(let cause): return "Recoverable(\(cause))"
        case .reauthenticate(let reason): return "Reauthenticate(\(reason))"
        case .stepUp: return "StepUp"
        case .configuration(let detail): return "Configuration(\(detail))"
        }
    }

    private func origin(of issuer: String) -> String {
        guard let url = URL(string: issuer), let scheme = url.scheme, let host = url.host else { return issuer }
        return "\(scheme)://\(host)\(url.port.map { ":\($0)" } ?? "")"
    }
}

/// The SDK's warnings and notes, onto the screen.
private struct LogLines: OAuthLogger {
    let write: @Sendable (String) -> Void
    func info(_ message: String) { write("sdk: \(message)") }
    func warn(_ message: String) { write("sdk warning: \(message)") }
}
