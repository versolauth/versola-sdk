import XCTest

/// The system browser leg against a real provider (Keycloak), on a simulator, driving the real
/// `ASWebAuthenticationSession` sheet the way a user does: the system asks whether the app may
/// use "localhost" to sign in, the provider's own login page loads in the sheet, alice types
/// her password, and the callback returns to the app. What `HttpLoginBrowser` (the conformance
/// tier) replaces with an HTTP conversation is exercised here.
///
/// Skipped unless `ISSUER` (the provider's issuer as its discovery announces it) is in the test
/// runner's environment: `TEST_RUNNER_ISSUER=... xcodebuild test` (`develop.md`).
///
/// The redirect is a private-use scheme (`com.example.versola.devicetier://app/oauth`): a
/// Universal Link needs an apple-app-site-association served over https from a host this machine
/// does not control.
///
/// Scenario ids: 01 (the browser half of the happy path), 12 (a redirect delivered to a
/// terminated app), 15 (state mismatch) and 18 (logout); the cancel table of
/// `spec/state-machine.md`.
@MainActor
final class BrowserLegUITests: XCTestCase {
    private static let alice = "alice"
    private var issuer = ""
    private var keycloak: Keycloak!
    private var app: XCUIApplication!

    override func setUp() async throws {
        continueAfterFailure = false
        guard let issuer = ProcessInfo.processInfo.environment["ISSUER"], !issuer.isEmpty else {
            throw XCTSkip("no ISSUER in the environment: the browser-leg tier is not configured")
        }
        self.issuer = issuer
        keycloak = Keycloak(issuer: issuer)
        try await keycloak.endSessions(of: Self.alice)
        // Safari and the sign-in sheet share cookies; the provider-side session is what matters.
        app = XCUIApplication()
        app.launchEnvironment["ISSUER"] = issuer
        // A clean app: the first launch wipes whatever an earlier test left (no stored grant, no
        // pending request); later launches in a test keep what the test made.
        app.terminate()
        app.launchArguments = ["-resetState", "YES"]
        app.launch()
        app.launchArguments = []
        XCTAssertTrue(app.buttons["login"].waitForExistence(timeout: 20), "the host app did not come up")
    }

    override func tearDown() async throws {
        app?.terminate()
    }

    // MARK: Tests

    func testBrowserOpensAliceSignsInCallbackReturnsAndLogoutEndsTheProviderSession() async throws {
        app.buttons["login"].tap()
        let sheet = try await awaitLoginForm()
        XCTAssertTrue(sheet.state == .runningForeground, "the sign-in sheet is the system's, in its own process")

        submitCredentials(in: sheet)

        let log = try await awaitLog("login: ok")
        XCTAssertLessThan(try XCTUnwrap(log.range(of: "state: authorizing")).lowerBound,
                          try XCTUnwrap(log.range(of: "state: authenticated")).lowerBound,
                          "authorizing, then authenticated\n\(log)")
        XCTAssertTrue(log.contains("claims: preferred_username=alice issuer=\(issuer)"), "claims hold alice\n\(log)")
        let sessions = try await keycloak.sessions(of: Self.alice)
        XCTAssertEqual(sessions, 1, "the provider holds the session the browser created")

        app.buttons["token"].tap()
        let used = try await awaitLog("userinfo: preferred_username=alice")
        XCTAssertTrue(used.contains("accessToken: present=true type=Bearer"), "accessToken() returns a token the provider accepts\n\(used)")

        app.buttons["logout"].tap()
        let after = try await awaitLog("logout: sessionEnded=true tokenRevoked=true")
        XCTAssertTrue(after.components(separatedBy: "login: ok").last!.contains("state: unauthenticated"), "signed out locally\n\(after)")
        let remaining = try await keycloak.sessions(of: Self.alice)
        XCTAssertEqual(remaining, 0, "the provider's session ended")
    }

    func testCancelFromTheSheetIsAUserCancelAndWipesThePendingRequest() async throws {
        app.buttons["login"].tap()
        let sheet = try await awaitLoginForm()

        sheet.buttons["Cancel"].tap()

        let log = try await awaitLog("login: failed Recoverable(userCancelled)")
        XCTAssertTrue(log.contains("state: authorizing"), log)
        _ = try await awaitLog("state: unauthenticated")
        // A wiped request leaves nothing to restore: a cold start reports unauthenticated, where
        // a kept one would report authorizing.
        app.terminate()
        app.launch()
        let restarted = try await awaitLog("state: ").components(separatedBy: "process: started").last!
        XCTAssertTrue(restarted.contains("state: unauthenticated"), "the pending request was wiped\n\(restarted)")
        XCTAssertFalse(restarted.contains("state: authorizing"), restarted)
    }

    func testTheAppSentToTheBackgroundAndBackKeepsThePendingRequestAndTheSignInCompletes() async throws {
        app.buttons["login"].tap()
        let sheet = try await awaitLoginForm()

        XCUIDevice.shared.press(.home)
        try await Task.sleep(for: .seconds(2))
        app.activate()

        let log = app.staticTexts["status"].label
        XCTAssertFalse(log.contains("login: failed"), "backgrounding is not a cancel\n\(log)")
        let form = try await awaitLoginForm()
        submitCredentials(in: form)
        let done = try await awaitLog("login: ok")
        XCTAssertTrue(done.contains("state: authenticated"), done)
    }

    func testARedirectOpenedByTheSystemAgainstATerminatedAppReachesTheRestoredRequestAndIsRefusedWithAWrongState() async throws {
        app.buttons["login"].tap()
        _ = try await awaitLoginForm()

        // The sheet lives and dies with the app: terminating it is the process death of scenario
        // 12. What survives is the pending request.
        app.terminate()
        // Opened by the system, as a browser would hand over the redirect of a Universal Link or
        // a custom scheme: the terminated app is started by the URL.
        XCUIDevice.shared.system.open(URL(string: "com.example.versola.devicetier://app/oauth?code=forged&state=forged&iss=\(issuer)")!)
        let open = XCUIApplication(bundleIdentifier: "com.apple.springboard").alerts.buttons["Open"]
        // The system asks "Open in ...?" for a custom scheme the first time in a session, and not
        // again after: the question is answered when it is asked.
        if open.waitForExistence(timeout: 5) { open.tap() }

        XCTAssertTrue(app.wait(for: .runningForeground, timeout: 20), "the redirect cold-started the app")
        let log = try await awaitLog("resume: failed")
        let restarted = log.components(separatedBy: "process: started").last!
        XCTAssertTrue(restarted.contains("state: authorizing"), "the pending request survived: the app observes authorizing\n\(restarted)")
        let first = restarted.split(separator: "\n").first { $0.hasPrefix("state: ") }
        XCTAssertEqual(first, "state: authorizing", "never unauthenticated on cold start\n\(restarted)")
        XCTAssertTrue(restarted.contains("redirect: taken by the SDK"), restarted)
        XCTAssertTrue(restarted.contains("resume: failed Configuration(stateMismatch)"), "refused as a state mismatch\n\(restarted)")
    }

    // MARK: Driving the system

    /// "Wants to use localhost to sign in": the system's question before every sheet, the
    /// end-session one included; answered Continue.
    private func acceptSignInPrompt() {
        let prompt = XCUIApplication(bundleIdentifier: "com.apple.springboard").alerts.firstMatch
        if prompt.exists, prompt.buttons["Continue"].exists { prompt.buttons["Continue"].tap() }
    }

    /// Answers the system's "wants to use localhost to sign in" prompt and waits for the
    /// provider's login form in the sheet.
    private func awaitLoginForm() async throws -> XCUIApplication {
        let sheet = XCUIApplication(bundleIdentifier: "com.apple.SafariViewService")
        let deadline = Date().addingTimeInterval(60)
        while Date() < deadline {
            acceptSignInPrompt()
            if sheet.textFields["Username or email"].exists { return sheet }
            try await Task.sleep(for: .milliseconds(500))
        }
        XCTFail("the provider's login form did not appear in the sheet\n\(app.staticTexts["status"].label)")
        return sheet
    }

    /// Types alice's credentials from the realm into the form and submits it. The keyboard covers
    /// the password field once it is up, so the form assistant's Next moves there rather than a
    /// tap, and the keyboard's own Go key submits.
    private func submitCredentials(in sheet: XCUIApplication) {
        let user = sheet.textFields["Username or email"]
        user.tap()
        XCTAssertTrue(sheet.keyboards.firstMatch.waitForExistence(timeout: 10), "the keyboard for the username")
        Thread.sleep(forTimeInterval: 1)
        sheet.typeText("alice")
        sheet.buttons["Next"].tap()
        Thread.sleep(forTimeInterval: 1)
        sheet.typeText("alice-password")
        let go = sheet.keyboards.buttons["go"].exists ? sheet.keyboards.buttons["go"] : sheet.keyboards.buttons["Go"]
        go.tap()
    }

    /// The screen, kept with the result: what a failing run was looking at.
    private func snapshot(_ name: String) {
        let attachment = XCTAttachment(screenshot: XCUIScreen.main.screenshot())
        attachment.name = name
        attachment.lifetime = .keepAlways
        add(attachment)
    }

    private func awaitLog(_ fragment: String, timeout: TimeInterval = 45) async throws -> String {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            acceptSignInPrompt()
            if app.state == .runningForeground {
                let log = app.staticTexts["status"].label
                if log.contains(fragment) { return log }
            }
            try await Task.sleep(for: .milliseconds(500))
        }
        snapshot("timeout")
        XCTFail("timed out waiting for \"\(fragment)\"; host log:\n\(app.staticTexts["status"].label)")
        return ""
    }
}
