import AuthenticationServices
import XCTest
@testable import OAuthClient

final class WebAuthenticationBrowserTests: XCTestCase {
    private let redirect = URL(string: "https://app.example.com/callback?code=abc&state=s")!

    private func browser() -> WebAuthenticationBrowser {
        // The closures are never called on the host: there is no window to present over.
        WebAuthenticationBrowser(
            presentationAnchor: { fatalError("no window on a test host") }, appState: { true }, logger: nil
        )
    }

    // MARK: outcome mapping

    func testRedirectURLBecomesARedirectOutcome() throws {
        let outcome = try WebAuthenticationBrowser.outcome(for: .success(redirect), foreground: true).get()
        XCTAssertEqual(outcome, .redirect(redirect))
        // Foreground or not does not matter to a delivered redirect.
        XCTAssertEqual(try WebAuthenticationBrowser.outcome(for: .success(redirect), foreground: false).get(), .redirect(redirect))
    }

    func testCanceledLoginInTheForegroundIsAUserCancel() throws {
        let error = ASWebAuthenticationSessionError(.canceledLogin)
        XCTAssertEqual(try WebAuthenticationBrowser.outcome(for: .failure(error), foreground: true).get(), .userCancelled)
    }

    func testCanceledLoginInTheBackgroundIsASystemCancel() throws {
        let error = ASWebAuthenticationSessionError(.canceledLogin)
        XCTAssertEqual(try WebAuthenticationBrowser.outcome(for: .failure(error), foreground: false).get(), .systemCancelled)
    }

    func testPresentationContextErrorsAreNoBrowserAvailable() {
        for code in [ASWebAuthenticationSessionError.Code.presentationContextInvalid, .presentationContextNotProvided] {
            for foreground in [true, false] {
                let result = WebAuthenticationBrowser.outcome(for: .failure(ASWebAuthenticationSessionError(code)), foreground: foreground)
                XCTAssertEqual(result, .failure(.configuration(.noBrowserAvailable)))
            }
        }
    }

    func testAnyOtherErrorIsNoBrowserAvailableWithAWarningThatNamesNoURL() {
        let logger = RecordingLogger()
        let secret = URL(string: "https://app.example.com/callback?code=SECRETCODE")!
        let error = NSError(domain: "SomeDomain", code: 42, userInfo: [NSURLErrorFailingURLErrorKey: secret, NSLocalizedDescriptionKey: secret.absoluteString])
        let result = WebAuthenticationBrowser.outcome(for: .failure(error), foreground: true, logger: logger)
        XCTAssertEqual(result, .failure(.configuration(.noBrowserAvailable)))
        XCTAssertEqual(logger.warnings.count, 1)
        XCTAssertFalse(logger.warnings[0].contains("SECRETCODE"))
        XCTAssertFalse(logger.warnings[0].contains("example.com"))
        XCTAssertTrue(logger.warnings[0].contains("SomeDomain"))
    }

    func testExpectedErrorsLogNothing() {
        let logger = RecordingLogger()
        _ = WebAuthenticationBrowser.outcome(for: .failure(ASWebAuthenticationSessionError(.canceledLogin)), foreground: true, logger: logger)
        _ = WebAuthenticationBrowser.outcome(for: .failure(ASWebAuthenticationSessionError(.presentationContextInvalid)), foreground: true, logger: logger)
        XCTAssertTrue(logger.warnings.isEmpty)
    }

    // MARK: callback derivation

    func testHttpsRedirectIsMatchedByHostAndPath() throws {
        XCTAssertEqual(
            try WebAuthenticationBrowser.callbackSpec(for: URL(string: "https://App.Example.com/cb/path")!),
            .https(host: "app.example.com", path: "/cb/path")
        )
        XCTAssertEqual(try WebAuthenticationBrowser.callbackSpec(for: URL(string: "https://app.example.com")!), .https(host: "app.example.com", path: "/"))
    }

    func testPrivateUseSchemeIsMatchedByScheme() throws {
        XCTAssertEqual(try WebAuthenticationBrowser.callbackSpec(for: URL(string: "com.example.app:/callback")!), .customScheme("com.example.app"))
    }

    func testCleartextRedirectCannotBeInterceptedAndIsRefused() {
        XCTAssertThrowsError(try WebAuthenticationBrowser.callbackSpec(for: URL(string: "http://127.0.0.1:5000/cb")!)) {
            guard case OAuthError.configuration(.invalidConfiguration) = $0 else { return XCTFail("\($0)") }
        }
    }

    // MARK: authorize without a redirect URI

    func testAuthorizeWithoutARedirectURIThrowsInvalidConfigurationBeforeAnythingOpens() async {
        do {
            _ = try await browser().authorize(URL(string: "https://auth.example.com/authorize")!, options: BrowserSessionOptions())
            XCTFail("expected invalidConfiguration")
        } catch {
            XCTAssertEqual(error as? OAuthError, .configuration(.invalidConfiguration(detail: "a redirect URI is needed to open the browser")))
        }
    }

    // MARK: pending redirects

    func testRedirectDeliveredBeforeTheAwaitIsBufferedAndReturned() async throws {
        let redirects = PendingRedirects()
        await redirects.deliver(redirect)
        let received = try await redirects.next()
        XCTAssertEqual(received, redirect)
    }

    func testBufferIsOneSlotAndTheNewestWins() async throws {
        let redirects = PendingRedirects()
        let older = URL(string: "https://app.example.com/callback?state=old")!
        await redirects.deliver(older)
        await redirects.deliver(redirect)
        let received = try await redirects.next()
        XCTAssertEqual(received, redirect)
    }

    func testAwaitThenDeliverCompletesTheWaiter() async throws {
        let redirects = PendingRedirects()
        async let received = redirects.next()
        // Deliver until the waiter has registered: a delivery that beats it is buffered and the
        // waiter would take it, so either order completes; no sleep needed.
        await redirects.deliver(redirect)
        let url = try await received
        XCTAssertEqual(url, redirect)
    }

    func testDrainDropsAStaleRedirect() async throws {
        let redirects = PendingRedirects()
        await redirects.deliver(redirect)
        await redirects.drain()
        let task = Task { try await redirects.next() }
        task.cancel()
        do {
            _ = try await task.value
            XCTFail("a drained redirect must not be delivered")
        } catch is CancellationError {
        }
    }

    func testCancellingTheWaiterEndsItWithCancellation() async {
        let redirects = PendingRedirects()
        let task = Task { try await redirects.next() }
        task.cancel()
        do {
            _ = try await task.value
            XCTFail("expected cancellation")
        } catch is CancellationError {
        } catch {
            XCTFail("\(error)")
        }
    }

    func testAwaitPendingRedirectReturnsADeliveredURLAsARedirect() async throws {
        let browser = browser()
        await browser.deliver(redirect)
        let outcome = try await browser.awaitPendingRedirect()
        XCTAssertEqual(outcome, .redirect(redirect))
    }
}
