import os
import XCTest
@testable import OAuthCore

final class AuthorizationFlowTests: XCTestCase {
    private struct Fixture {
        let flow: AuthorizationFlow
        let store: MemoryPendingStore
        let hub: SessionStateHub
    }

    private func fixture(
        browser: BrowserAuthorizationSession,
        metadata: ProviderMetadata = AuthzKit.metadata(),
        store: MemoryPendingStore = MemoryPendingStore(),
        hasStoredGrant: Bool = false,
        grantProbe: (@Sendable () async throws -> Bool)? = nil,
        tokenBinding: TokenBinding = .bearer,
        dpopKey: DpopProofSource? = nil,
        starter: AuthorizationStarter? = nil,
        now: Date = AuthzKit.now,
        configuration: CoreConfiguration = AuthzKit.configuration,
        logger: (any OAuthLogger)? = nil
    ) -> Fixture {
        let hub = SessionStateHub()
        let discovery = DiscoveryService(
            issuer: AuthzKit.issuer, client: StaticDiscoveryClient(metadata: metadata), cache: MemoryMetadataCache())
        let flow = AuthorizationFlow(
            configuration: configuration, discovery: discovery, pendingStore: store, browser: browser,
            states: hub, tokenBinding: tokenBinding, dpopKey: dpopKey, clock: Clock(now: { now }),
            hasStoredGrant: grantProbe ?? { hasStoredGrant }, starter: starter, logger: logger
        )
        return Fixture(flow: flow, store: store, hub: hub)
    }

    private func assertAuthorizeFails(
        _ expected: OAuthError, _ f: Fixture, file: StaticString = #filePath, line: UInt = #line
    ) async {
        do {
            _ = try await f.flow.authorize(scopes: ["openid"])
            XCTFail("expected \(expected)", file: file, line: line)
        } catch {
            XCTAssertEqual(error as? OAuthError, expected, file: file, line: line)
        }
    }

    // MARK: Persistence order

    func testThePendingRequestIsSavedAndTheStateIsAuthorizingBeforeTheBrowserOpens() async throws {
        let store = MemoryPendingStore()
        let hub = Box<SessionState?>(nil)
        let savesAtOpen = Box(-1)
        let storedAtOpen = Box<PendingAuthorizationRequest?>(nil)
        let holder = Box<SessionStateHub?>(nil)
        let browser = ScriptedBrowser { uri, _ in
            await savesAtOpen.set(await store.saveCount)
            await storedAtOpen.set(await store.stored)
            if let h = await holder.value { await hub.set(await h.current) }
            return .redirect(AuthzKit.redirect(answering: uri))
        }
        let f = fixture(browser: browser, store: store)
        await holder.set(f.hub)

        let grant = try await f.flow.authorize(scopes: ["openid", "profile"])

        let saves = await savesAtOpen.value
        XCTAssertEqual(saves, 1)
        let atOpen = await storedAtOpen.value
        let openedFirst = await browser.opened[0]
        XCTAssertEqual(atOpen?.state, AuthorizationResponseValidator.stateOf(openedFirst))
        let stateAtOpen = await hub.value
        XCTAssertEqual(stateAtOpen, .authorizing)
        // The grant leaves the flow still authorizing, with the request stored.
        let current = await f.hub.current
        XCTAssertEqual(current, .authorizing)
        let stored = await store.stored
        XCTAssertEqual(stored?.state, grant.state)
        XCTAssertEqual(grant.code, "code-1")
        XCTAssertEqual(grant.scopes, ["openid", "profile"])
        XCTAssertEqual(grant.nonce, stored?.nonce)
    }

    func testTheBrowserIsOpenedOnTheDiscoveredEndpointWithTheConfiguredRedirectAndOptions() async throws {
        let browser = ScriptedBrowser.answering()
        let f = fixture(browser: browser)
        _ = try await f.flow.authorize(scopes: ["openid"], ephemeralBrowser: true)
        let uri = await browser.opened[0]
        XCTAssertTrue(uri.absoluteString.hasPrefix("https://id.example.com/authorize?response_type=code"))
        let options = await browser.options[0]
        let stored = await f.store.stored
        XCTAssertEqual(
            options,
            BrowserSessionOptions(ephemeral: true, redirectURI: URL(string: AuthzKit.redirect), expectedState: stored?.state),
            "the browser is told the state of the request it waits for the response to"
        )
        XCTAssertNotNil(stored)
    }

    func testAStarterBuildsTheRequestAndItsPendingRecordIsWhatIsSaved() async throws {
        let browser = ScriptedBrowser { uri, _ in .redirect(AuthzKit.redirect(answering: uri)) }
        let f = fixture(browser: browser, starter: FixedStarter())
        let grant = try await f.flow.authorize(scopes: ["openid"])
        let stored = await f.store.stored
        XCTAssertEqual(stored?.extensions, ["blob": "sealed"])
        XCTAssertEqual(grant.extensions, ["blob": "sealed"])
        let opened = await browser.opened[0]
        XCTAssertTrue(opened.absoluteString.contains("request_uri=urn%3Ax"))
    }

    // MARK: Cancel and failure

    func testUserCancelWipesThePendingRequestAndSettlesUnauthenticated() async {
        let f = fixture(browser: ScriptedBrowser.outcome(.userCancelled))
        await assertAuthorizeFails(.recoverable(.userCancelled), f)
        let stored = await f.store.stored
        let state = await f.hub.current
        XCTAssertNil(stored)
        XCTAssertEqual(state, .unauthenticated)
    }

    func testUserCancelOverAStoredGrantSettlesAuthenticated() async {
        let f = fixture(browser: ScriptedBrowser.outcome(.userCancelled), hasStoredGrant: true)
        await assertAuthorizeFails(.recoverable(.userCancelled), f)
        let stored = await f.store.stored
        let state = await f.hub.current
        XCTAssertNil(stored)
        XCTAssertEqual(state, .authenticated)
    }

    func testSystemCancelKeepsThePendingRequestAndTheAuthorizingState() async {
        let f = fixture(browser: ScriptedBrowser.outcome(.systemCancelled))
        await assertAuthorizeFails(.recoverable(.systemCancelled), f)
        let stored = await f.store.stored
        let state = await f.hub.current
        XCTAssertNotNil(stored)
        XCTAssertEqual(state, .authorizing)
    }

    func testABrowserErrorClearsThePendingRequestAndSettlesTheState() async {
        let f = fixture(browser: ScriptedBrowser.failing(OAuthError.configuration(.noBrowserAvailable)))
        await assertAuthorizeFails(.configuration(.noBrowserAvailable), f)
        let stored = await f.store.stored
        let state = await f.hub.current
        XCTAssertNil(stored)
        XCTAssertEqual(state, .unauthenticated)
    }

    func testACancelledCallerWipesThePendingRequestSinceTheSessionIsGone() async {
        // On this platform the cancellation dismissed the sheet: nothing can redirect, and a
        // request left behind would refuse every login for ten minutes (the iOS note in
        // `spec/state-machine.md`'s cancel section).
        let f = fixture(browser: ScriptedBrowser.failing(CancellationError()))
        do {
            _ = try await f.flow.authorize(scopes: ["openid"])
            XCTFail("expected cancellation")
        } catch is CancellationError {
        } catch {
            XCTFail("unexpected \(error)")
        }
        let stored = await f.store.stored
        let state = await f.hub.current
        XCTAssertNil(stored)
        XCTAssertEqual(state, .unauthenticated)
    }

    // MARK: Redirect validation

    func testARedirectWhoseStateIsNotThePendingRequestsIsIgnoredAndTheGenuineOneCompletesTheLogin() async throws {
        // Scenario 15. The redirect URI is public, so a URL for it with a state this request never
        // sent is not its response: ignored, not a failure, and what comes after still answers.
        let logger = LoggedLines()
        let calls = Box(0)
        let browser = ScriptedBrowser(
            onAuthorize: { uri, _ in .redirect(AuthzKit.redirect(answering: uri, state: "forged")) },
            onAwait: { opened in
                let n = await calls.value + 1
                await calls.set(n)
                // The second is a redirect with no state at all; the third is the genuine one.
                if n == 1 { return .redirect(URL(string: AuthzKit.redirect + "?code=forged&iss=\(AuthzKit.issuer)")!) }
                return .redirect(AuthzKit.redirect(answering: opened.last!))
            }
        )
        let f = fixture(browser: browser, logger: logger)

        let grant = try await f.flow.authorize(scopes: ["openid"])

        XCTAssertEqual(grant.code, "code-1")
        let awaited = await browser.awaitCalls
        XCTAssertEqual(awaited, 2, "the foreign and the state-less redirect were each stepped over")
        let opened = await browser.opened
        XCTAssertEqual(opened.count, 1, "no second login, no second browser")
        let lines = logger.all
        XCTAssertEqual(lines.count, 1, "two ignored in the same instant are one line")
        let stored = await f.store.stored
        XCTAssertFalse(
            lines.contains { $0.contains("forged") || $0.contains(grant.state) || $0.contains("example.com") },
            "the log names no value of the URL or of the request: \(lines)"
        )
        XCTAssertEqual(stored?.state, grant.state, "the request the browser was opened for is the one that was answered")
    }

    func testWhileRedirectsThatAreNotItsResponseArriveTheLoginKeepsWaitingWithItsRequestAndState() async throws {
        let seen = Box(0)
        let browser = ScriptedBrowser(
            onAuthorize: { uri, _ in .redirect(AuthzKit.redirect(answering: uri, state: "forged-0")) },
            onAwait: { _ in
                let n = await seen.value + 1
                await seen.set(n)
                if n <= 5 { return .redirect(AuthzKit.redirect(answering: URL(string: "https://x.example.com/")!, state: "forged-\(n)")) }
                try await Task.sleep(nanoseconds: 3_600_000_000_000)
                throw CancellationError()
            }
        )
        let f = fixture(browser: browser)

        let login = Task { try await f.flow.authorize(scopes: ["openid"]) }
        await AuthzKit.waitUntil("every foreign redirect to be consumed") { await seen.value == 6 }

        let stored = await f.store.stored
        let state = await f.hub.current
        let saves = await f.store.saveCount
        let inFlight = await f.flow.authorizationInFlight
        XCTAssertNotNil(stored, "the pending request is kept")
        XCTAssertEqual(saves, 1)
        XCTAssertEqual(state, .authorizing)
        XCTAssertTrue(inFlight, "the login is still carried out, neither failed nor abandoned")
        login.cancel()
        _ = try? await login.value
    }

    func testTheUserDismissingTheBrowserAfterARedirectWasIgnoredStillEndsTheLoginAsACancel() async {
        let browser = ScriptedBrowser(
            onAuthorize: { uri, _ in .redirect(AuthzKit.redirect(answering: uri, state: "forged")) },
            onAwait: { _ in .userCancelled }
        )
        let f = fixture(browser: browser)
        await assertAuthorizeFails(.recoverable(.userCancelled), f)
        let stored = await f.store.stored
        let state = await f.hub.current
        XCTAssertNil(stored)
        XCTAssertEqual(state, .unauthenticated)
    }

    func testARedirectCarryingTheRightStateButNeitherCodeNorErrorIsMalformed() async {
        let browser = ScriptedBrowser { uri, _ in .redirect(AuthzKit.redirect(answering: uri, code: nil)) }
        let f = fixture(browser: browser)
        await assertAuthorizeFails(.configuration(.malformedAuthorizationResponse), f)
        let stored = await f.store.stored
        XCTAssertNil(stored)
    }

    func testAMissingIssFailsWhenTheMetadataAdvertisedSupportAtRequestTime() async {
        let browser = ScriptedBrowser { uri, _ in .redirect(AuthzKit.redirect(answering: uri, iss: nil)) }
        let f = fixture(browser: browser, metadata: AuthzKit.metadata(issSupported: true))
        await assertAuthorizeFails(.configuration(.issuerMismatch(expected: AuthzKit.issuer, received: nil)), f)
    }

    func testAnAuthorizationErrorIsMappedAndClearsThePendingRequest() async {
        let browser = ScriptedBrowser { uri, _ in
            .redirect(AuthzKit.redirect(answering: uri, code: nil, extra: [("error", "access_denied")]))
        }
        let f = fixture(browser: browser, hasStoredGrant: true)
        await assertAuthorizeFails(.reauthenticate(.authorizationDenied), f)
        let stored = await f.store.stored
        let state = await f.hub.current
        XCTAssertNil(stored)
        XCTAssertEqual(state, .authenticated)
    }

    func testARedirectForAnAbandonedEarlierRequestIsSkippedNotFailedAsAMismatch() async throws {
        let abandonedState = Box<String?>(nil)
        let calls = Box(0)
        let browser = ScriptedBrowser(
            onAuthorize: { uri, _ in
                let n = await calls.value + 1
                await calls.set(n)
                if n == 1 {
                    await abandonedState.set(AuthorizationResponseValidator.stateOf(uri))
                    throw CancellationError()
                }
                // The forgotten first tab redirects before the second one does.
                let stale = await abandonedState.value
                return .redirect(AuthzKit.redirect(answering: uri, state: stale))
            },
            onAwait: { opened in .redirect(AuthzKit.redirect(answering: opened.last!)) }
        )
        let f = fixture(browser: browser)
        do {
            _ = try await f.flow.authorize(scopes: ["openid"])
            XCTFail("expected cancellation")
        } catch is CancellationError {}

        let grant = try await f.flow.authorize(scopes: ["openid"])

        let opened = await browser.opened
        XCTAssertEqual(grant.state, AuthorizationResponseValidator.stateOf(opened[1]))
        XCTAssertNotEqual(grant.state, AuthorizationResponseValidator.stateOf(opened[0]))
        let awaits = await browser.awaitCalls
        XCTAssertEqual(awaits, 1)
    }

    func testARedirectForAStateNoRequestOfThisProcessIssuedIsSkippedToo() async throws {
        // The abandoned-tab skip used to be limited to states this process itself had issued, and
        // anything else failed as a mismatch. Now every redirect that is not the request's own is
        // stepped over, however many.
        let seen = Box(0)
        let browser = ScriptedBrowser(
            onAuthorize: { uri, _ in .redirect(AuthzKit.redirect(answering: uri, state: "never-issued")) },
            onAwait: { opened in
                let n = await seen.value + 1
                await seen.set(n)
                if n <= 25 { return .redirect(AuthzKit.redirect(answering: opened.last!, state: "never-issued-\(n)")) }
                return .redirect(AuthzKit.redirect(answering: opened.last!))
            }
        )
        let f = fixture(browser: browser)
        let grant = try await f.flow.authorize(scopes: ["openid"])
        XCTAssertEqual(grant.code, "code-1")
        let awaits = await browser.awaitCalls
        XCTAssertEqual(awaits, 26)
    }

    func testIgnoredRedirectsAreLoggedAtMostOncePerSecondCountingTheOnesTheLineLeavesOut() async throws {
        let logger = LoggedLines()
        let calls = Box(0)
        let clock = Clock(now: { AuthzKit.now.addingTimeInterval(Double(Self.offset.withLock { $0 })) })
        let hub = SessionStateHub()
        let browser = ScriptedBrowser(
            onAuthorize: { uri, _ in .redirect(AuthzKit.redirect(answering: uri, state: "stranger-0")) },
            onAwait: { opened in
                let n = await calls.value + 1
                await calls.set(n)
                // A second and a half passes between the third ignored redirect and the fourth.
                if n == 3 { Self.offset.withLock { $0 = 1.5 } }
                if n <= 4 { return .redirect(AuthzKit.redirect(answering: opened.last!, state: "stranger-\(n)")) }
                return .redirect(AuthzKit.redirect(answering: opened.last!))
            }
        )
        Self.offset.withLock { $0 = 0 }
        let discovery = DiscoveryService(
            issuer: AuthzKit.issuer, client: StaticDiscoveryClient(metadata: AuthzKit.metadata()), cache: MemoryMetadataCache())
        let flow = AuthorizationFlow(
            configuration: AuthzKit.configuration, discovery: discovery, pendingStore: MemoryPendingStore(), browser: browser,
            states: hub, clock: clock, logger: logger
        )

        _ = try await flow.authorize(scopes: ["openid"])

        let lines = logger.all
        XCTAssertEqual(lines.count, 2, "\(lines)")
        XCTAssertTrue(lines[0].contains("(1 so far"), lines[0])
        XCTAssertTrue(lines[1].contains("(4 so far"), lines[1])
    }

    private static let offset = OSAllocatedUnfairLock(initialState: 0.0)

    func testTheLogLineCarriesTheErrorCodeOfAnIgnoredProviderErrorNeverItsDescription() async {
        // A provider that answers with an error and no state: nothing to match it with, so it is
        // ignored, and the one thing the developer needs is why the login waits.
        let logger = LoggedLines()
        let calls = Box(0)
        let browser = ScriptedBrowser(
            onAuthorize: { _, _ in .redirect(URL(string: AuthzKit.redirect + "?error=access_denied&error_description=the+user+said+SECRET+words")!) },
            onAwait: { _ in
                let n = await calls.value + 1
                await calls.set(n)
                if n == 1 { return .redirect(URL(string: AuthzKit.redirect + "?error=%3Cscript%3Ealert(1)%3C%2Fscript%3E&state=other")!) }
                return .userCancelled
            }
        )
        let f = fixture(browser: browser, logger: logger)
        await assertAuthorizeFails(.recoverable(.userCancelled), f)
        let lines = logger.all
        XCTAssertEqual(lines.count, 1)
        XCTAssertTrue(lines[0].contains("error=access_denied"), lines[0])
        XCTAssertFalse(lines[0].contains("SECRET") || lines[0].contains("script"), lines[0])
    }

    // MARK: A login that waits is bounded by its request's ten minutes

    /// A clock that reads `creation` when the request is built and `later` from then on.
    private func ticking(creation: Date, later: Date) -> Clock {
        let calls = OSAllocatedUnfairLock(initialState: 0)
        return Clock(now: { calls.withLock { n in defer { n += 1 }; return n == 0 ? creation : later } })
    }

    private func flowWith(clock: Clock, browser: BrowserAuthorizationSession, hasStoredGrant: Bool = false) -> Fixture {
        let hub = SessionStateHub()
        let store = MemoryPendingStore()
        let discovery = DiscoveryService(
            issuer: AuthzKit.issuer, client: StaticDiscoveryClient(metadata: AuthzKit.metadata()), cache: MemoryMetadataCache())
        let flow = AuthorizationFlow(
            configuration: AuthzKit.configuration, discovery: discovery, pendingStore: store, browser: browser,
            states: hub, clock: clock, hasStoredGrant: { hasStoredGrant }
        )
        return Fixture(flow: flow, store: store, hub: hub)
    }

    func testALoginWhoseSheetNeverAnswersEndsWithTheRequestsExpiryAndTheSlotWiped() async {
        let sleeping = ScriptedBrowser(onAuthorize: { _, _ in
            try await Task.sleep(nanoseconds: 3_600_000_000_000)
            throw CancellationError()
        })
        let clock = ticking(creation: AuthzKit.now, later: AuthzKit.now.addingTimeInterval(PendingAuthorizationRequest.maxAge - 0.05))
        let f = flowWith(clock: clock, browser: sleeping)

        await assertAuthorizeFails(.recoverable(.pendingRequestExpired), f)

        let stored = await f.store.stored
        let state = await f.hub.current
        let inFlight = await f.flow.authorizationInFlight
        XCTAssertNil(stored)
        XCTAssertEqual(state, .unauthenticated)
        XCTAssertFalse(inFlight)
    }

    func testALoginThatKeepsBeingHandedRedirectsThatAreNotItsResponseEndsTheSameWay() async {
        let browser = ScriptedBrowser(
            onAuthorize: { uri, _ in .redirect(AuthzKit.redirect(answering: uri, state: "stranger")) },
            onAwait: { opened in
                try await Task.sleep(nanoseconds: 10_000_000)
                return .redirect(AuthzKit.redirect(answering: opened.last!, state: "stranger"))
            }
        )
        let clock = ticking(creation: AuthzKit.now, later: AuthzKit.now.addingTimeInterval(PendingAuthorizationRequest.maxAge - 0.1))
        let f = flowWith(clock: clock, browser: browser)

        await assertAuthorizeFails(.recoverable(.pendingRequestExpired), f)

        let stored = await f.store.stored
        XCTAssertNil(stored)
    }

    func testALoginThatExpiresOverAStoredGrantSettlesAuthenticated() async {
        let sleeping = ScriptedBrowser(onAuthorize: { _, _ in
            try await Task.sleep(nanoseconds: 3_600_000_000_000)
            throw CancellationError()
        })
        let clock = ticking(creation: AuthzKit.now, later: AuthzKit.now.addingTimeInterval(PendingAuthorizationRequest.maxAge))
        let f = flowWith(clock: clock, browser: sleeping, hasStoredGrant: true)
        await assertAuthorizeFails(.recoverable(.pendingRequestExpired), f)
        let state = await f.hub.current
        XCTAssertEqual(state, .authenticated)
    }

    func testALoginAnsweredInTimeIsNotTouchedByTheBound() async throws {
        let clock = ticking(creation: AuthzKit.now, later: AuthzKit.now.addingTimeInterval(PendingAuthorizationRequest.maxAge - 1))
        let f = flowWith(clock: clock, browser: ScriptedBrowser.answering())
        let grant = try await f.flow.authorize(scopes: ["openid"])
        XCTAssertEqual(grant.code, "code-1")
    }

    // MARK: A sheet that ended on a redirect that is not the response

    func testASheetThatEndedOnAForeignStateFailsTheLoginAsAStateMismatchAndWipesTheRequest() async {
        // What `WebAuthenticationBrowser` reports when its own session completes with it.
        let f = fixture(browser: ScriptedBrowser.failing(OAuthError.configuration(.stateMismatch)))
        await assertAuthorizeFails(.configuration(.stateMismatch), f)
        let stored = await f.store.stored
        let state = await f.hub.current
        XCTAssertNil(stored)
        XCTAssertEqual(state, .unauthenticated)
    }

    // MARK: Discovery-driven checks

    func testAnAdvertisedChallengeMethodListWithoutS256IsProviderUnsupportedBeforeAnythingIsSaved() async {
        let browser = ScriptedBrowser.answering()
        let f = fixture(browser: browser, metadata: AuthzKit.metadata(challengeMethods: ["plain"]))
        await assertAuthorizeFails(.configuration(.providerUnsupported(capability: "S256")), f)
        let saves = await f.store.saveCount
        let opened = await browser.opened
        XCTAssertEqual(saves, 0)
        XCTAssertTrue(opened.isEmpty)
    }

    func testS256InTheAdvertisedListOrNoListAtAllIsAccepted() async throws {
        for methods in [["S256"], ["plain", "S256"], []] {
            let f = fixture(browser: ScriptedBrowser.answering(), metadata: AuthzKit.metadata(challengeMethods: methods))
            let grant = try await f.flow.authorize(scopes: ["openid"])
            XCTAssertEqual(grant.code, "code-1")
        }
    }

    // MARK: DPoP binding

    private func jkt(of browser: ScriptedBrowser) async -> String? {
        await AuthorizationResponseValidator.parseQuery(browser.opened[0])["dpop_jkt"]
    }

    func testDpopJktIsSentWhenBoundAndTheProviderAdvertisesDpop() async throws {
        let browser = ScriptedBrowser.answering()
        let f = fixture(browser: browser, metadata: AuthzKit.metadata(dpop: true),
                        tokenBinding: .dpop(), dpopKey: FixedDpopSource())
        _ = try await f.flow.authorize(scopes: ["openid"])
        let sent = await jkt(of: browser)
        XCTAssertEqual(sent, "jkt-example-thumbprint")
    }

    func testNoDpopJktUnderBearerEvenWithAKeyHandedIn() async throws {
        let browser = ScriptedBrowser.answering()
        let f = fixture(browser: browser, metadata: AuthzKit.metadata(dpop: true), dpopKey: FixedDpopSource())
        _ = try await f.flow.authorize(scopes: ["openid"])
        let sent = await jkt(of: browser)
        XCTAssertNil(sent)
    }

    func testNoDpopJktWhenTheProviderDoesNotAdvertiseDpopAndItIsNotRequired() async throws {
        let browser = ScriptedBrowser.answering()
        let f = fixture(browser: browser, tokenBinding: .dpop(), dpopKey: FixedDpopSource())
        _ = try await f.flow.authorize(scopes: ["openid"])
        let sent = await jkt(of: browser)
        XCTAssertNil(sent)
    }

    func testRequiredDpopAgainstAProviderWithoutItIsProviderUnsupportedBeforeAnythingIsSaved() async {
        let browser = ScriptedBrowser.answering()
        let f = fixture(browser: browser, tokenBinding: .dpop(required: true), dpopKey: FixedDpopSource())
        await assertAuthorizeFails(.configuration(.providerUnsupported(capability: "dpop")), f)
        let saves = await f.store.saveCount
        XCTAssertEqual(saves, 0)
    }

    func testABindingWithoutAKeyIsAnInvalidConfigurationNotASilentlyUnboundLogin() async {
        let f = fixture(browser: ScriptedBrowser.answering(), metadata: AuthzKit.metadata(dpop: true), tokenBinding: .dpop())
        do {
            _ = try await f.flow.authorize(scopes: ["openid"])
            XCTFail("expected a failure")
        } catch OAuthError.configuration(.invalidConfiguration) {
        } catch {
            XCTFail("unexpected \(error)")
        }
        let saves = await f.store.saveCount
        XCTAssertEqual(saves, 0)
    }

    func testAStarterThatBindsTheKeyItselfGetsNoDpopJktFromTheFlow() async throws {
        let captured = Box<String?>("unset")
        struct Spy: AuthorizationStarter {
            let captured: Box<String?>
            var bindsDpopKeyItself: Bool { true }
            func start(request: AuthorizationRequest, metadata: ProviderMetadata, now: Date) async throws
                -> StartedAuthorization {
                await captured.set(request.dpopJkt)
                return try await FixedStarter().start(request: request, metadata: metadata, now: now)
            }
        }
        let f = fixture(browser: ScriptedBrowser.answering(), metadata: AuthzKit.metadata(dpop: true),
                        tokenBinding: .dpop(), dpopKey: FixedDpopSource(), starter: Spy(captured: captured))
        _ = try await f.flow.authorize(scopes: ["openid"])
        let seen = await captured.value
        XCTAssertNil(seen, "the starter was not called, or the flow set dpop_jkt")
    }

    // MARK: Serialisation

    func testASecondAuthorizeWhileTheFirstAwaitsTheBrowserIsRefusedNotQueued() async throws {
        // A double tap on Sign in: the second call is refused under the gate, so it cannot open
        // a second sheet once the first completes (`spec/oauth-sdk-api.md` section 5).
        let browser = GatedBrowser()
        let f = fixture(browser: browser)
        let first = Task { try await f.flow.authorize(scopes: ["openid"]) }
        await AuthzKit.waitUntil("the first authorization opens the browser") { await browser.opened.count == 1 }

        do {
            _ = try await f.flow.authorize(scopes: ["openid"])
            XCTFail("the second authorization was not refused")
        } catch let error as OAuthError {
            guard case .configuration(.invalidConfiguration) = error else { return XCTFail("\(error)") }
        }

        let opened = await browser.opened
        let saves = await f.store.saveCount
        XCTAssertEqual(opened.count, 1)
        XCTAssertEqual(saves, 1, "the refused authorization overwrote the pending request")
        await browser.resolveNext(.redirect(AuthzKit.redirect(answering: opened[0])))
        let grant = try await first.value
        XCTAssertEqual(grant.state, AuthorizationResponseValidator.stateOf(opened[0]))
    }

    /// The state of the authorization a URL opened, for scripting the redirect of an older one.
    private func redirect(forState state: String) -> BrowserOutcome {
        .redirect(AuthzKit.redirect(answering: URL(string: "https://x.example.com/?state=\(state)")!))
    }

    func testALoginAfterASystemCancelSupersedesTheLeftoverRequestInsteadOfBeingRefused() async throws {
        let first = Box<String?>(nil)
        let browser = ScriptedBrowser(
            onAuthorize: { uri, _ in
                if let previous = await first.value {
                    // The abandoned tab redirects before the new one does.
                    _ = previous
                    return .redirect(AuthzKit.redirect(answering: uri, state: previous))
                }
                await first.set(AuthorizationResponseValidator.stateOf(uri))
                return .systemCancelled
            },
            onAwait: { opened in .redirect(AuthzKit.redirect(answering: opened.last!)) }
        )
        let f = fixture(browser: browser)
        do {
            _ = try await f.flow.authorize(scopes: ["openid"])
            XCTFail("expected systemCancelled")
        } catch {
            XCTAssertEqual(error as? OAuthError, .recoverable(.systemCancelled))
        }
        let leftover = await f.flow.authorizationInFlight
        let state = await f.hub.current
        XCTAssertFalse(leftover, "nobody awaits the leftover request: it does not block a new login")
        XCTAssertEqual(state, .authorizing, "and it stays resumable until something replaces it")

        let grant = try await f.flow.authorize(scopes: ["openid"])

        let opened = await browser.opened
        XCTAssertEqual(opened.count, 2)
        XCTAssertEqual(grant.state, AuthorizationResponseValidator.stateOf(opened[1]), "the new request won; the old tab's redirect was stepped over")
        let saves = await f.store.saveCount
        XCTAssertEqual(saves, 2)
    }

    func testALoginIsRefusedWhileTheGrantItProducedIsBeingRedeemed() async throws {
        let f = fixture(browser: ScriptedBrowser.answering())
        _ = try await f.flow.authorize(scopes: ["openid"])
        let inFlight = await f.flow.authorizationInFlight
        XCTAssertTrue(inFlight, "between the redirect and completeLogin() the code exchange is the authorization")

        do {
            _ = try await f.flow.authorize(scopes: ["openid"])
            XCTFail("a second login would have its slot cleared by the first one's completion")
        } catch let error as OAuthError {
            guard case .configuration(.invalidConfiguration) = error else { return XCTFail("\(error)") }
        }

        try await f.flow.completeLogin()
        let after = await f.flow.authorizationInFlight
        XCTAssertFalse(after)
        _ = try await f.flow.authorize(scopes: ["openid"])
    }

    /// A resume that has only a redirect left to wait for is not an authorization in flight (the
    /// facade ends it for a new login), yet it still holds the gate: the flow itself must not let
    /// a second authorization share the browser with it.
    func testAResumeWaitingForItsRedirectIsNotInFlightButStillRefusesAnAuthorizationAtTheFlow() async throws {
        let browser = ScriptedBrowser { uri, _ in .redirect(AuthzKit.redirect(answering: uri)) }
        let f = fixture(browser: browser, store: MemoryPendingStore(AuthzKit.pending(createdAt: AuthzKit.now - 60)))
        let resume = Task { try await f.flow.resumePendingAuthorization() }
        await AuthzKit.waitUntil("the resume waits for its redirect") { await browser.awaitCalls == 1 }

        let waiting = await f.flow.isAwaitingRedirect
        let inFlight = await f.flow.authorizationInFlight
        XCTAssertTrue(waiting)
        XCTAssertFalse(inFlight)
        do {
            _ = try await f.flow.authorize(scopes: ["openid"])
            XCTFail("a second holder of the gate")
        } catch let error as OAuthError {
            guard case .configuration(.invalidConfiguration) = error else { return XCTFail("\(error)") }
        }

        resume.cancel()
        _ = try? await resume.value
        let after = await f.flow.isAwaitingRedirect
        XCTAssertFalse(after)
        let grant = try await f.flow.authorize(scopes: ["openid"])
        XCTAssertNotNil(grant, "once the wait is ended the gate is free and the leftover is superseded")
    }

    func testAnAbandonedExchangeFreesTheFlowToo() async throws {
        let f = fixture(browser: ScriptedBrowser.answering())
        _ = try await f.flow.authorize(scopes: ["openid"])
        await f.flow.abandonLogin()
        let inFlight = await f.flow.authorizationInFlight
        XCTAssertFalse(inFlight)
    }

    /// The race: `authorize` has returned the grant (the gate is free) and `completeLogin()` has
    /// not run yet, so the request is still in the store. A resume admitted here used to wait out
    /// the request's ten minutes for a redirect that was already consumed, holding the gate.
    func testResumeWhileTheLoginInThisProcessIsRedeemingItsCodeFindsNothingToWaitFor() async throws {
        let browser = ScriptedBrowser(
            onAuthorize: { uri, _ in .redirect(AuthzKit.redirect(answering: uri)) },
            onAwait: { _ in throw TransportFailure() }
        )
        let f = fixture(browser: browser)
        _ = try await f.flow.authorize(scopes: ["openid"])

        let resumed = try await f.flow.resumePendingAuthorization()

        XCTAssertNil(resumed)
        let waits = await browser.awaitCalls
        XCTAssertEqual(waits, 0)
        let inFlight = await f.flow.authorizationInFlight
        XCTAssertTrue(inFlight, "the login's own completion is still pending")
        let state = await f.hub.current
        XCTAssertEqual(state, .authorizing)
    }

    func testAnEndSessionWaitingBehindTheBrowserThatIsCancelledLeavesTheQueue() async throws {
        // `endSession` and `resumePendingAuthorization` still queue behind an open browser; a
        // waiter cancelled while queued leaves without opening anything.
        let browser = GatedBrowser()
        let f = fixture(browser: browser)
        let first = Task { try await f.flow.authorize(scopes: ["openid"]) }
        await AuthzKit.waitUntil("the first authorization opens the browser") { await browser.opened.count == 1 }
        let waiting = Task { try await f.flow.endSession(idTokenHint: nil) }
        for _ in 0..<200 { await Task.yield() }
        waiting.cancel()
        do {
            _ = try await waiting.value
            XCTFail("expected cancellation")
        } catch is CancellationError {}

        let opened = await browser.opened
        await browser.resolveNext(.redirect(AuthzKit.redirect(answering: opened[0])))
        _ = try await first.value
        let after = await browser.opened
        XCTAssertEqual(after.count, 1)
    }

    // MARK: Restore

    func testRestoreWithAYoungPendingRequestPublishesAuthorizing() async throws {
        let f = fixture(browser: ScriptedBrowser.answering(), store: MemoryPendingStore(AuthzKit.pending(createdAt: AuthzKit.now - 60)))
        try await f.flow.ensureRestored()
        let state = await f.hub.current
        XCTAssertEqual(state, .authorizing)
    }

    func testRestoreWithAnExpiredPendingRequestDiscardsItAndPublishesUnauthenticated() async throws {
        let store = MemoryPendingStore(AuthzKit.pending(createdAt: AuthzKit.now - 601))
        let f = fixture(browser: ScriptedBrowser.answering(), store: store)
        try await f.flow.ensureRestored()
        let state = await f.hub.current
        let stored = await store.stored
        XCTAssertEqual(state, .unauthenticated)
        XCTAssertNil(stored)
    }

    func testAStoredGrantOutranksAPendingRequestWhichIsDiscarded() async throws {
        let store = MemoryPendingStore(AuthzKit.pending(createdAt: AuthzKit.now - 60))
        let f = fixture(browser: ScriptedBrowser.answering(), store: store, hasStoredGrant: true)
        try await f.flow.ensureRestored()
        let state = await f.hub.current
        let stored = await store.stored
        XCTAssertEqual(state, .authenticated)
        XCTAssertNil(stored)
    }

    /// A store behind a key that is not available: every read fails the way a locked Keychain does.
    private actor LockedPendingStore: PendingAuthorizationStore {
        var loads = 0
        var clears = 0
        func save(_ request: PendingAuthorizationRequest) async throws { throw OAuthError.recoverable(.unlockRequired) }
        func load() async throws -> PendingAuthorizationRequest? {
            loads += 1
            throw OAuthError.recoverable(.unlockRequired)
        }
        func clear() async throws { clears += 1 }
    }

    func testTheStoredGrantIsReadBeforeThePendingRequestSoALockedPendingSlotCannotHideIt() async throws {
        let store = LockedPendingStore()
        let hub = SessionStateHub()
        let discovery = DiscoveryService(issuer: AuthzKit.issuer, client: StaticDiscoveryClient(metadata: AuthzKit.metadata()), cache: MemoryMetadataCache())
        let flow = AuthorizationFlow(configuration: AuthzKit.configuration, discovery: discovery, pendingStore: store, browser: ScriptedBrowser.answering(), states: hub, clock: Clock(now: { AuthzKit.now }), hasStoredGrant: { true })

        try await flow.ensureRestored()

        let state = await hub.current
        XCTAssertEqual(state, .authenticated, "a returning user is not made to wait on, or be hidden by, the slot of a login that never finished")
        let loads = await store.loads
        XCTAssertEqual(loads, 0, "with a grant the pending request is discarded unread")
    }

    func testAGrantProbeThatNeedsTheUnlockPublishesLockedAndRestoresAfterwards() async throws {
        let locked = Box(true)
        let f = fixture(browser: ScriptedBrowser.answering(), grantProbe: {
            if await locked.value { throw OAuthError.recoverable(.unlockRequired) }
            return true
        })

        do {
            try await f.flow.ensureRestored()
            XCTFail("the failure was swallowed")
        } catch {
            XCTAssertEqual(error as? OAuthError, .recoverable(.unlockRequired))
        }
        let during = await f.hub.current
        XCTAssertEqual(during, .locked, "not a false unauthenticated: credentials may well be there")

        await locked.set(false)
        try await f.flow.ensureRestored()
        let after = await f.hub.current
        XCTAssertEqual(after, .authenticated, "the failed restore is retried, not remembered")
    }

    func testAPendingSlotThatNeedsTheUnlockPublishesLockedNotUnauthenticated() async throws {
        let hub = SessionStateHub()
        let discovery = DiscoveryService(issuer: AuthzKit.issuer, client: StaticDiscoveryClient(metadata: AuthzKit.metadata()), cache: MemoryMetadataCache())
        let flow = AuthorizationFlow(configuration: AuthzKit.configuration, discovery: discovery, pendingStore: LockedPendingStore(), browser: ScriptedBrowser.answering(), states: hub, clock: Clock(now: { AuthzKit.now }), hasStoredGrant: { false })

        do {
            try await flow.ensureRestored()
            XCTFail("the failure was swallowed")
        } catch {
            XCTAssertEqual(error as? OAuthError, .recoverable(.unlockRequired))
        }
        let state = await hub.current
        XCTAssertEqual(state, .locked)
    }

    func testAnUnreadableStoreOtherThanLockedIsThrownAndPublishesNothing() async throws {
        let f = fixture(browser: ScriptedBrowser.answering(), grantProbe: { throw OAuthError.configuration(.invalidConfiguration(detail: "keychain error -1")) })
        do {
            try await f.flow.ensureRestored()
            XCTFail("the failure was swallowed")
        } catch {
            XCTAssertEqual(error as? OAuthError, .configuration(.invalidConfiguration(detail: "keychain error -1")))
        }
        let state = await f.hub.current
        XCTAssertEqual(state, .unauthenticated, "the hub's initial value stands; the failure is the caller's to see")
    }

    func testRestoreWithNothingStoredPublishesUnauthenticatedAndRunsOnce() async throws {
        let store = MemoryPendingStore()
        let f = fixture(browser: ScriptedBrowser.answering(), store: store)
        try await f.flow.ensureRestored()
        try await store.save(AuthzKit.pending())
        try await f.flow.ensureRestored()
        let state = await f.hub.current
        XCTAssertEqual(state, .unauthenticated)
    }

    // MARK: Resume

    func testResumeWithNothingPendingIsNil() async throws {
        let f = fixture(browser: ScriptedBrowser.answering())
        let grant = try await f.flow.resumePendingAuthorization()
        XCTAssertNil(grant)
    }

    func testResumeOfAnExpiredPendingRequestIsPendingRequestExpired() async throws {
        let store = MemoryPendingStore(AuthzKit.pending(createdAt: AuthzKit.now - 700))
        let f = fixture(browser: ScriptedBrowser.answering(), store: store)
        do {
            _ = try await f.flow.resumePendingAuthorization()
            XCTFail("expected pendingRequestExpired")
        } catch {
            XCTAssertEqual(error as? OAuthError, .recoverable(.pendingRequestExpired))
        }
        let stored = await store.stored
        let state = await f.hub.current
        XCTAssertNil(stored)
        XCTAssertEqual(state, .unauthenticated)
        // The expiry is reported once; afterwards nothing is pending.
        let again = try await f.flow.resumePendingAuthorization()
        XCTAssertNil(again)
    }

    func testResumeValidatesAnAwaitedRedirectAgainstTheRestoredRequest() async throws {
        let pending = AuthzKit.pending(state: "restored-state", createdAt: AuthzKit.now - 60)
        let browser = ScriptedBrowser(
            onAuthorize: { _, _ in .userCancelled },
            onAwait: { _ in .redirect(AuthzKit.redirect(answering: URL(string: "https://x.example.com/?state=restored-state")!)) }
        )
        let f = fixture(browser: browser, store: MemoryPendingStore(pending))
        let grant = try await f.flow.resumePendingAuthorization()
        XCTAssertEqual(grant?.state, "restored-state")
        XCTAssertEqual(grant?.code, "code-1")
        let opened = await browser.opened
        XCTAssertTrue(opened.isEmpty, "resume must not open a browser")
        let state = await f.hub.current
        XCTAssertEqual(state, .authorizing)
    }

    func testResumeStepsOverRedirectsWhoseStateIsNotTheRestoredOneAndCompletesWithTheGenuine() async throws {
        let pending = AuthzKit.pending(state: "restored-state", createdAt: AuthzKit.now - 60)
        let seen = Box(0)
        let browser = ScriptedBrowser(
            onAuthorize: { _, _ in .userCancelled },
            onAwait: { _ in
                let n = await seen.value + 1
                await seen.set(n)
                let state = n == 1 ? "forged" : "restored-state"
                return .redirect(AuthzKit.redirect(answering: URL(string: "https://x.example.com/?state=\(state)")!))
            }
        )
        let store = MemoryPendingStore(pending)
        let f = fixture(browser: browser, store: store)

        let grant = try await f.flow.resumePendingAuthorization()

        XCTAssertEqual(grant?.state, "restored-state")
        let stored = await store.stored
        XCTAssertNotNil(stored, "the request stays until the coordinator completes the login")
    }

    func testAResumeThatIsOnlyHandedForeignRedirectsKeepsItsRequestUntilItExpires() async {
        // 50 ms of the ten minutes remain; nothing but a redirect that is not the request's arrives.
        let pending = AuthzKit.pending(state: "restored-state", createdAt: AuthzKit.now - (PendingAuthorizationRequest.maxAge - 0.05))
        let seen = Box(0)
        let browser = ScriptedBrowser(
            onAuthorize: { _, _ in .userCancelled },
            onAwait: { _ in
                if await seen.value == 0 {
                    await seen.set(1)
                    return .redirect(AuthzKit.redirect(answering: URL(string: "https://x.example.com/?state=forged")!))
                }
                try await Task.sleep(nanoseconds: 3_600_000_000_000)
                throw CancellationError()
            }
        )
        let store = MemoryPendingStore(pending)
        let f = fixture(browser: browser, store: store)
        do {
            _ = try await f.flow.resumePendingAuthorization()
            XCTFail("expected pendingRequestExpired")
        } catch {
            XCTAssertEqual(error as? OAuthError, .recoverable(.pendingRequestExpired))
        }
        let awaited = await seen.value
        XCTAssertEqual(awaited, 1, "the foreign redirect was consumed, and the resume went on waiting until the request's end")
    }

    func testResumeGivesUpWhenTheRedirectNeverComesWithinTheRemainingLifetime() async {
        // 50 ms of the ten minutes remain, by the injected clock; the browser delivers nothing.
        let store = MemoryPendingStore(AuthzKit.pending(createdAt: AuthzKit.now - (PendingAuthorizationRequest.maxAge - 0.05)))
        let f = fixture(browser: ScriptedBrowser.answering(), store: store)
        do {
            _ = try await f.flow.resumePendingAuthorization()
            XCTFail("expected pendingRequestExpired")
        } catch {
            XCTAssertEqual(error as? OAuthError, .recoverable(.pendingRequestExpired))
        }
        let stored = await store.stored
        let state = await f.hub.current
        XCTAssertNil(stored)
        XCTAssertEqual(state, .unauthenticated)
    }

    func testResumeAfterASystemCancelKeepsThePendingRequest() async {
        let pending = AuthzKit.pending(createdAt: AuthzKit.now - 60)
        let browser = ScriptedBrowser(onAuthorize: { _, _ in .userCancelled }, onAwait: { _ in .systemCancelled })
        let store = MemoryPendingStore(pending)
        let f = fixture(browser: browser, store: store)
        do {
            _ = try await f.flow.resumePendingAuthorization()
            XCTFail("expected systemCancelled")
        } catch {
            XCTAssertEqual(error as? OAuthError, .recoverable(.systemCancelled))
        }
        let stored = await store.stored
        XCTAssertNotNil(stored)
    }

    // MARK: End session

    private func endSessionFlow(
        metadata: ProviderMetadata = AuthzKit.metadata(), _ onAuthorize: @escaping ScriptedBrowser.OnAuthorize
    ) -> (Fixture, ScriptedBrowser) {
        let browser = ScriptedBrowser(onAuthorize: onAuthorize)
        return (fixture(browser: browser, metadata: metadata), browser)
    }

    func testEndSessionIsTrueOnlyWhenTheRedirectCarriesTheStateThatWasSent() async throws {
        let (f, browser) = endSessionFlow { uri, _ in
            .redirect(URL(string: "\(AuthzKit.postLogout)?state=\(AuthorizationResponseValidator.stateOf(uri)!)")!)
        }
        let ended = try await f.flow.endSession(idTokenHint: "id-token-hint-value")
        XCTAssertTrue(ended)

        let uri = await browser.opened[0]
        let query = AuthorizationResponseValidator.parseQuery(uri)
        XCTAssertTrue(uri.absoluteString.hasPrefix("https://id.example.com/logout?"))
        XCTAssertEqual(query["id_token_hint"], "id-token-hint-value")
        XCTAssertEqual(query["post_logout_redirect_uri"], AuthzKit.postLogout)
        XCTAssertEqual(query["client_id"], "client-123", "RP-Initiated Logout 1.0: names the client when the hint alone could be missing or expired")
        XCTAssertGreaterThanOrEqual(query["state"]?.count ?? 0, 43)
        let options = await browser.options[0]
        XCTAssertFalse(options.ephemeral)
        XCTAssertEqual(options.redirectURI, URL(string: AuthzKit.postLogout))
    }

    /// With no `postLogoutRedirectUri` configured the provider is told of none, but the page is
    /// still opened: skipping it left the provider's single sign-on session alive on a shared
    /// device with `sessionEnded = false` and no word to anyone. The session still needs a callback
    /// to be created; the login redirect is the one the app already has.
    func testEndSessionWithoutAPostLogoutRedirectUriStillOpensThePageAndSendsNoRedirect() async throws {
        let configuration = CoreConfiguration(issuer: AuthzKit.issuer, clientId: "client-123", redirectUri: URL(string: AuthzKit.redirect)!)
        let browser = ScriptedBrowser { _, _ in .userCancelled }
        let f = fixture(browser: browser, configuration: configuration)

        let ended = try await f.flow.endSession(idTokenHint: "hint")

        XCTAssertFalse(ended, "nothing acknowledged: the redirect cannot come back")
        let opened = await browser.opened
        XCTAssertEqual(opened.count, 1, "the end-session page was opened")
        let query = AuthorizationResponseValidator.parseQuery(opened[0])
        XCTAssertNil(query["post_logout_redirect_uri"])
        XCTAssertEqual(query["client_id"], "client-123")
        XCTAssertEqual(query["id_token_hint"], "hint")
        let options = await browser.options[0]
        XCTAssertEqual(options.redirectURI, URL(string: AuthzKit.redirect))
        XCTAssertFalse(options.ephemeral)
    }

    func testARedirectForThePostLogoutUriWithAnotherOrNoStateIsIgnoredAndTheSignOutWaitsForTheRealOne() async throws {
        let told = Box<String?>(nil)
        let calls = Box(0)
        let browser = ScriptedBrowser(
            onAuthorize: { _, options in
                await told.set(options.expectedState)
                return .redirect(URL(string: "\(AuthzKit.postLogout)?state=forged")!)
            },
            onAwait: { opened in
                let n = await calls.value + 1
                await calls.set(n)
                if n == 1 { return .redirect(URL(string: AuthzKit.postLogout)!) }
                let state = AuthorizationResponseValidator.stateOf(opened[0])!
                return .redirect(URL(string: "\(AuthzKit.postLogout)?state=\(state)")!)
            }
        )
        let logger = LoggedLines()
        let f = fixture(browser: browser, logger: logger)

        let ended = try await f.flow.endSession(idTokenHint: nil)

        XCTAssertTrue(ended, "the provider's own redirect acknowledged it")
        let opened = await browser.opened
        let awaited = await told.value
        XCTAssertEqual(awaited, AuthorizationResponseValidator.stateOf(opened[0]), "the browser is told the state the sign-out sent")
        XCTAssertEqual(logger.all.count, 1)
    }

    func testTheUserClosingTheSignedOutPageAfterAForeignRedirectWasIgnoredIsNotAcknowledged() async throws {
        let browser = ScriptedBrowser(
            onAuthorize: { _, _ in .redirect(URL(string: "\(AuthzKit.postLogout)?state=forged")!) },
            onAwait: { _ in .userCancelled }
        )
        let f = fixture(browser: browser)
        let ended = try await f.flow.endSession(idTokenHint: nil)
        XCTAssertFalse(ended)
        let awaited = await browser.awaitCalls
        XCTAssertEqual(awaited, 1, "it waited on after the foreign redirect")
    }

    func testASignOutSheetThatEndedOnAForeignStateIsNotAcknowledgedAndThrowsNothing() async throws {
        let (f, _) = endSessionFlow { _, _ in throw OAuthError.configuration(.stateMismatch) }
        let ended = try await f.flow.endSession(idTokenHint: nil)
        XCTAssertFalse(ended)
    }

    func testEndSessionWithoutAHintOmitsIt() async throws {
        let (f, browser) = endSessionFlow { _, _ in .userCancelled }
        _ = try await f.flow.endSession(idTokenHint: nil)
        let uri = await browser.opened[0]
        XCTAssertNil(AuthorizationResponseValidator.parseQuery(uri)["id_token_hint"])
    }

    func testEndSessionIsFalseWhenTheUserOrTheSystemEndsTheBrowser() async throws {
        for outcome in [BrowserOutcome.userCancelled, .systemCancelled] {
            let (f, _) = endSessionFlow { _, _ in outcome }
            let ended = try await f.flow.endSession(idTokenHint: "hint")
            XCTAssertFalse(ended)
        }
    }

    func testEndSessionIsFalseWhenTheBrowserFailsToLaunch() async throws {
        let (f, _) = endSessionFlow { _, _ in throw OAuthError.configuration(.noBrowserAvailable) }
        let ended = try await f.flow.endSession(idTokenHint: "hint")
        XCTAssertFalse(ended)
    }

    func testEndSessionWithoutAnEndpointIsFalseAndOpensNothing() async throws {
        let (f, browser) = endSessionFlow(metadata: AuthzKit.metadata(endSession: false)) { _, _ in .userCancelled }
        let ended = try await f.flow.endSession(idTokenHint: "hint")
        let opened = await browser.opened
        XCTAssertFalse(ended)
        XCTAssertTrue(opened.isEmpty)
    }

    func testEndSessionPropagatesCancellationOfItsCaller() async {
        let (f, _) = endSessionFlow { _, _ in throw CancellationError() }
        do {
            _ = try await f.flow.endSession(idTokenHint: "hint")
            XCTFail("expected cancellation")
        } catch is CancellationError {
        } catch {
            XCTFail("unexpected \(error)")
        }
    }

    // MARK: Coordinator hooks

    func testAbandonLoginClearsThePendingRequestAndSettlesUnauthenticatedWithoutAGrant() async throws {
        let f = fixture(browser: ScriptedBrowser.answering())
        _ = try await f.flow.authorize(scopes: ["openid"])
        await f.flow.abandonLogin()
        let stored = await f.store.stored
        let state = await f.hub.current
        XCTAssertNil(stored)
        XCTAssertEqual(state, .unauthenticated)
    }

    func testAbandonLoginSettlesAuthenticatedWhenAGrantIsStored() async throws {
        let f = fixture(browser: ScriptedBrowser.answering(), hasStoredGrant: true)
        _ = try await f.flow.authorize(scopes: ["openid"])
        var state = await f.hub.current
        XCTAssertEqual(state, .authorizing)
        await f.flow.abandonLogin()
        let stored = await f.store.stored
        state = await f.hub.current
        XCTAssertNil(stored)
        XCTAssertEqual(state, .authenticated)
    }

    func testCompleteLoginClearsThePendingRequestAndPublishesAuthenticated() async throws {
        let f = fixture(browser: ScriptedBrowser.answering())
        _ = try await f.flow.authorize(scopes: ["openid"])
        try await f.flow.completeLogin()
        let stored = await f.store.stored
        let state = await f.hub.current
        XCTAssertNil(stored)
        XCTAssertEqual(state, .authenticated)
    }

    func testCompleteLogoutClearsAnyPendingRequestAndPublishesUnauthenticated() async throws {
        let f = fixture(browser: ScriptedBrowser.failing(CancellationError()), hasStoredGrant: true)
        _ = try? await f.flow.authorize(scopes: ["openid"])
        await f.flow.completeLogout()
        let stored = await f.store.stored
        let state = await f.hub.current
        XCTAssertNil(stored)
        XCTAssertEqual(state, .unauthenticated)
    }

    func testStepUpIsEnteredOnlyFromAuthenticated() async throws {
        let f = fixture(browser: ScriptedBrowser.answering(), hasStoredGrant: true)
        try await f.flow.ensureRestored()
        await f.flow.enterStepUpRequired()
        var state = await f.hub.current
        XCTAssertEqual(state, .stepUpRequired)

        await f.flow.setState(.refreshing)
        await f.flow.enterStepUpRequired()
        state = await f.hub.current
        XCTAssertEqual(state, .refreshing)
    }

    func testSetStatePublishesToObservers() async {
        let f = fixture(browser: ScriptedBrowser.answering())
        var iterator = await f.hub.stream().makeAsyncIterator()
        _ = await iterator.next()
        await f.flow.setState(.locked)
        let next = await iterator.next()
        XCTAssertEqual(next, .locked)
    }
}
