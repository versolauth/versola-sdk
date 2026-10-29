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
        tokenBinding: TokenBinding = .bearer,
        dpopKey: DpopProofSource? = nil,
        starter: AuthorizationStarter? = nil,
        now: Date = AuthzKit.now
    ) -> Fixture {
        let hub = SessionStateHub()
        let discovery = DiscoveryService(
            issuer: AuthzKit.issuer, client: StaticDiscoveryClient(metadata: metadata), cache: MemoryMetadataCache())
        let flow = AuthorizationFlow(
            configuration: AuthzKit.configuration, discovery: discovery, pendingStore: store, browser: browser,
            states: hub, tokenBinding: tokenBinding, dpopKey: dpopKey, clock: Clock(now: { now }),
            hasStoredGrant: { hasStoredGrant }, starter: starter
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
        XCTAssertEqual(options, BrowserSessionOptions(ephemeral: true, redirectURI: URL(string: AuthzKit.redirect)))
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

    func testARedirectFailingValidationClearsThePendingRequestAndRethrows() async {
        let browser = ScriptedBrowser { uri, _ in .redirect(AuthzKit.redirect(answering: uri, state: "forged")) }
        let f = fixture(browser: browser)
        await assertAuthorizeFails(.configuration(.stateMismatch), f)
        let stored = await f.store.stored
        let state = await f.hub.current
        XCTAssertNil(stored)
        XCTAssertEqual(state, .unauthenticated)
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

    func testARedirectForAnUnknownStateIsNotSkippedAndFailsAsAMismatch() async {
        let browser = ScriptedBrowser(
            onAuthorize: { uri, _ in .redirect(AuthzKit.redirect(answering: uri, state: "never-issued")) },
            onAwait: { opened in .redirect(AuthzKit.redirect(answering: opened.last!)) }
        )
        let f = fixture(browser: browser)
        await assertAuthorizeFails(.configuration(.stateMismatch), f)
        let awaits = await browser.awaitCalls
        XCTAssertEqual(awaits, 0)
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

    func testResumeRefusesARedirectWhoseStateIsNotTheRestoredOne() async {
        let pending = AuthzKit.pending(state: "restored-state", createdAt: AuthzKit.now - 60)
        let browser = ScriptedBrowser(
            onAuthorize: { _, _ in .userCancelled },
            onAwait: { _ in .redirect(AuthzKit.redirect(answering: URL(string: "https://x.example.com/?state=forged")!)) }
        )
        let store = MemoryPendingStore(pending)
        let f = fixture(browser: browser, store: store)
        do {
            _ = try await f.flow.resumePendingAuthorization()
            XCTFail("expected stateMismatch")
        } catch {
            XCTAssertEqual(error as? OAuthError, .configuration(.stateMismatch))
        }
        let stored = await store.stored
        XCTAssertNil(stored)
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
        XCTAssertGreaterThanOrEqual(query["state"]?.count ?? 0, 43)
        let options = await browser.options[0]
        XCTAssertFalse(options.ephemeral)
        XCTAssertEqual(options.redirectURI, URL(string: AuthzKit.postLogout))
    }

    func testEndSessionIsFalseForAWrongOrMissingState() async throws {
        let (wrong, _) = endSessionFlow { _, _ in .redirect(URL(string: "\(AuthzKit.postLogout)?state=forged")!) }
        let a = try await wrong.flow.endSession(idTokenHint: nil)
        XCTAssertFalse(a)
        let (missing, _) = endSessionFlow { _, _ in .redirect(URL(string: AuthzKit.postLogout)!) }
        let b = try await missing.flow.endSession(idTokenHint: nil)
        XCTAssertFalse(b)
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
