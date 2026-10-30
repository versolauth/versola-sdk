import Foundation
import os
import XCTest
@testable import OAuthCore

/// The retry budget against server-side answers (`spec/retry-policy.md`; scenarios 34 to 36):
/// which failures are repeated, how long it waits (the server's `Retry-After` in preference to
/// the backoff, never shortened to fit), when it stops, and the cooldown it leaves behind. Time
/// and randomness are injected; nothing here sleeps.
final class RetryBudgetServerErrorTests: XCTestCase {
    private let origin = "https://id.example.com"
    private let otherOrigin = "https://api.example.com"

    /// One clock for both readings the budget makes: the wall clock (elapsed in an operation)
    /// and the monotonic one (the cooldown), advanced together by the fake `sleep`.
    final class World: Sendable {
        private let seconds = OSAllocatedUnfairLock(initialState: 0.0)
        private let slept = OSAllocatedUnfairLock(initialState: [TimeInterval]())
        var delays: [TimeInterval] { slept.withLock { $0 } }
        func advance(_ delta: TimeInterval) { seconds.withLock { $0 += delta } }
        var clock: Clock {
            Clock(
                now: { Date(timeIntervalSince1970: 1_700_000_000 + self.seconds.withLock { $0 }) },
                uptime: { 5000 + self.seconds.withLock { $0 } }
            )
        }
        var sleep: @Sendable (TimeInterval) async throws -> Void {
            { delay in
                self.slept.withLock { $0.append(delay) }
                self.advance(delay)
            }
        }
    }

    /// Random bytes that read as one fixed fraction of the range, so jitter is a number.
    struct FixedRandom: RandomSource {
        let fraction: Double
        func bytes(_ count: Int) -> [UInt8] {
            let value = UInt64(fraction * 1_000_000)
            return (0..<count).map { index in UInt8((value >> UInt64(8 * (count - 1 - index))) & 0xFF) }
        }
    }

    private func budget(
        _ world: World, policy: RetryPolicy = .default, fraction: Double = 0, cooldown: RetryCooldown? = nil
    ) -> RetryBudget {
        policy.newBudget(clock: world.clock, random: FixedRandom(fraction: fraction), cooldown: cooldown, sleep: world.sleep)
    }

    private func server(_ status: Int, retryAfter: Int64? = nil) -> OAuthError {
        .recoverable(.server(status: status, retryAfterMillis: retryAfter, attempts: 1, elapsedMillis: 0))
    }

    /// Fails with `failures` in order, then succeeds; counts the requests made.
    private func script(_ failures: [OAuthError], then value: Int = 7) -> (calls: Box<Int>, call: @Sendable () async throws -> Int) {
        let calls = Box(0)
        let queue = Box(failures)
        return (calls, {
            await calls.set(await calls.value + 1)
            var remaining = await queue.value
            if remaining.isEmpty { return value }
            let next = remaining.removeFirst()
            await queue.set(remaining)
            throw next
        })
    }

    private func failure(of body: () async throws -> some Any) async -> OAuthError? {
        do { _ = try await body(); return nil } catch { return error as? OAuthError }
    }

    // MARK: Retry-After in preference to the backoff

    func testARetryAfterIsWaitedInPreferenceToTheBackoff() async throws {
        let world = World()
        let s = script([server(429, retryAfter: 2000)])
        let value = try await budget(world).execute(origin: origin, s.call)
        XCTAssertEqual(value, 7)
        XCTAssertEqual(world.delays, [2.0], "no jitter at fraction 0, and not the 0.5 s backoff")
        let calls = await s.calls.value
        XCTAssertEqual(calls, 2)
    }

    func testTheJitterOnARetryAfterIsAtMostATenthAndAtMostASecond() async throws {
        let high = World()
        _ = try await budget(high, fraction: 0.999999).execute(origin: origin, script([server(503, retryAfter: 2000)]).call)
        XCTAssertEqual(high.delays.count, 1)
        XCTAssertGreaterThanOrEqual(high.delays[0], 2.0)
        XCTAssertLessThanOrEqual(high.delays[0], 2.2, "a tenth of 2 s")

        let large = World()
        let long = try RetryPolicy(totalBudget: 60)
        _ = try await budget(large, policy: long, fraction: 0.999999).execute(origin: origin, script([server(503, retryAfter: 30_000)]).call)
        XCTAssertGreaterThanOrEqual(large.delays[0], 30.0)
        XCTAssertLessThanOrEqual(large.delays[0], 31.0, "a tenth of 30 s is 3 s, capped at one")
    }

    func testTheJitterMayNotPushAWaitThatFitsPastTheBudget() async throws {
        let world = World()
        // 19.5 s fits in 20 s; a tenth of jitter (1.95 s, capped at 1 s) would not, so it is clipped to the room.
        _ = try await budget(world, fraction: 0.999999).execute(origin: origin, script([server(503, retryAfter: 19_500)]).call)
        XCTAssertLessThanOrEqual(world.delays[0], 20.0)
        XCTAssertGreaterThanOrEqual(world.delays[0], 19.5)
    }

    func testARetryAfterOfZeroRetriesAtOnceAndStillCountsAsAnAttempt() async {
        let world = World()
        let s = script([server(429, retryAfter: 0), server(429, retryAfter: 0), server(429, retryAfter: 0)])
        let error = await failure { try await self.budget(world).execute(origin: self.origin, s.call) }
        XCTAssertEqual(world.delays, [0, 0])
        let calls = await s.calls.value
        XCTAssertEqual(calls, 3, "three requests, as the default allowance says, not an endless loop")
        guard case .recoverable(.server(429, 0, let attempts, _))? = error else { return XCTFail("\(String(describing: error))") }
        XCTAssertEqual(attempts, 3)
    }

    // MARK: A Retry-After the budget cannot hold

    func testARetryAfterBeyondTheBudgetStopsAtOnceWithoutSleepingOrShorteningTheWait() async {
        let world = World()
        let s = script([server(429, retryAfter: 30_000)])
        let error = await failure { try await self.budget(world).execute(origin: self.origin, s.call) }
        XCTAssertEqual(world.delays, [], "it did not sleep")
        let calls = await s.calls.value
        XCTAssertEqual(calls, 1, "and did not retry early to fit the budget")
        guard case .recoverable(.server(429, 30_000, 1, _))? = error else { return XCTFail("\(String(describing: error))") }
    }

    func testADayLongRetryAfterCostsNoWaitingAndNoRequest() async {
        let world = World()
        let s = script([server(503, retryAfter: RetryAfter.ceilingMillis)])
        let error = await failure { try await self.budget(world).execute(origin: self.origin, s.call) }
        XCTAssertEqual(world.delays, [])
        guard case .recoverable(.server(503, RetryAfter.ceilingMillis, 1, _))? = error else { return XCTFail("\(String(describing: error))") }
    }

    func testARetryAfterThatFitsOnlyAfterTimeAlreadySpentIsMeasuredAgainstWhatIsLeft() async {
        let world = World()
        // The first answer asks for 12 s (fits: waited), the second for 12 s more (24 s > 20 s: stop).
        let s = script([server(503, retryAfter: 12_000), server(503, retryAfter: 12_000)])
        let error = await failure { try await self.budget(world).execute(origin: self.origin, s.call) }
        XCTAssertEqual(world.delays, [12.0])
        guard case .recoverable(.server(503, 12_000, 2, let elapsed))? = error else { return XCTFail("\(String(describing: error))") }
        XCTAssertEqual(elapsed, 12_000)
    }

    // MARK: Without Retry-After

    func testWithoutARetryAfterTheBackoffAppliesAndGrows() async {
        let world = World()
        let s = script([server(500), server(500), server(500)])
        let error = await failure { try await self.budget(world, fraction: 0.5).execute(origin: self.origin, s.call) }
        // Full jitter at one half: 0.25 s, then 0.5 s; the third failure ends the operation.
        XCTAssertEqual(world.delays, [0.25, 0.5])
        let calls = await s.calls.value
        XCTAssertEqual(calls, 3)
        XCTAssertEqual(error, .recoverable(.server(status: 500, retryAfterMillis: nil, attempts: 3, elapsedMillis: 750)))
    }

    func testAFiveHundredAndOneIsSurfacedAtOnceWithNoRetryAndNoDelay() async {
        let world = World()
        let s = script([server(501)])
        let error = await failure { try await self.budget(world).execute(origin: self.origin, s.call) }
        let calls = await s.calls.value
        XCTAssertEqual(calls, 1)
        XCTAssertEqual(world.delays, [])
        XCTAssertEqual(error, server(501))
    }

    func testATransportFailureIsStillRepeatedAsBefore() async throws {
        let world = World()
        let network = OAuthError.recoverable(.network(detail: "down", attempts: 1, elapsedMillis: 0))
        let s = script([network, network])
        let value = try await budget(world).execute(origin: origin, s.call)
        XCTAssertEqual(value, 7)
        XCTAssertEqual(world.delays.count, 2)
    }

    func testAnythingElseIsFinalAndPassesThroughUntouched() async {
        let world = World()
        for final in [OAuthError.reauthenticate(.grantRejected), .configuration(.stateMismatch), .recoverable(.nonceLoop(origin: origin)), .recoverable(.unlockRequired)] {
            let s = script([final])
            let error = await failure { try await self.budget(world).execute(origin: self.origin, s.call) }
            let calls = await s.calls.value
            XCTAssertEqual(calls, 1)
            XCTAssertEqual(error, final)
        }
    }

    // MARK: The allowances count failures

    func testRequestsThatSucceededDoNotSpendTheAllowanceOfOnesAfterThem() async {
        let world = World()
        let shared = budget(world)
        // Discovery, say, then a push on the same origin that fails every time: still three requests of its own.
        for _ in 0..<3 { _ = try? await shared.execute(origin: origin, { 1 }) }
        let s = script([server(500), server(500), server(500)])
        let error = await failure { try await shared.execute(origin: self.origin, s.call) }
        let calls = await s.calls.value
        XCTAssertEqual(calls, 3)
        guard case .recoverable(.server(500, nil, 3, _))? = error else { return XCTFail("\(String(describing: error))") }
    }

    func testFailuresOfOneCallSpendTheAllowanceOfTheNextOnTheSameOrigin() async {
        let world = World()
        let shared = budget(world)
        let first = script([server(500), server(500), server(500)])
        _ = await failure { try await shared.execute(origin: self.origin, first.call) }
        // Three failures at this origin: a second call is refused before it is sent, with the last failure.
        let second = script([])
        let error = await failure { try await shared.execute(origin: self.origin, second.call) }
        let sent = await second.calls.value
        XCTAssertEqual(sent, 0)
        guard case .recoverable(.server(500, nil, 0, _))? = error else { return XCTFail("\(String(describing: error))") }
    }

    func testAnotherOriginHasItsOwnPerOriginAllowanceButSharesTheTotal() async {
        let world = World()
        let shared = budget(world)
        let first = script([server(500), server(500)])
        _ = try? await shared.execute(origin: origin, first.call)          // two failures, then success
        let second = script([server(500), server(500), server(500)])
        let error = await failure { try await shared.execute(origin: self.otherOrigin, second.call) }
        let calls = await second.calls.value
        // The default total is four failures: two spent, so the other origin makes only two more requests.
        XCTAssertEqual(calls, 2)
        guard case .recoverable(.server(500, nil, 2, _))? = error else { return XCTFail("\(String(describing: error))") }
    }

    func testTheWallClockEndsAnOperationWhoseNextDelayWouldOutlastIt() async throws {
        let world = World()
        let tight = try RetryPolicy(initialBackoff: 2, maxBackoff: 2, totalBudget: 1)
        let s = script([server(500)])
        let error = await failure { try await self.budget(world, policy: tight, fraction: 0.999999).execute(origin: self.origin, s.call) }
        let calls = await s.calls.value
        XCTAssertEqual(calls, 1)
        XCTAssertEqual(world.delays, [])
        guard case .recoverable(.server(500, nil, 1, _))? = error else { return XCTFail("\(String(describing: error))") }
    }

    // MARK: The cooldown

    func testACooldownRefusesTheNextRequestToThatOriginWithoutSendingAnything() async {
        let world = World()
        let cooldown = RetryCooldown(clock: world.clock)
        let first = script([server(429, retryAfter: 30_000)])
        _ = await failure { try await self.budget(world, cooldown: cooldown).execute(origin: self.origin, first.call) }

        // Ten seconds later, in a new operation: refused here, with what is left of the wait.
        world.advance(10)
        let next = script([])
        let error = await failure { try await self.budget(world, cooldown: cooldown).execute(origin: self.origin, next.call) }
        let sent = await next.calls.value
        XCTAssertEqual(sent, 0)
        XCTAssertEqual(error, .recoverable(.server(status: 429, retryAfterMillis: 20_000, attempts: 0, elapsedMillis: 0)))
    }

    func testTheCooldownIsOverOnceTheTimeHasPassed() async throws {
        let world = World()
        let cooldown = RetryCooldown(clock: world.clock)
        _ = await failure { try await self.budget(world, cooldown: cooldown).execute(origin: self.origin, self.script([self.server(429, retryAfter: 30_000)]).call) }
        world.advance(30)
        let value = try await budget(world, cooldown: cooldown).execute(origin: origin, script([]).call)
        XCTAssertEqual(value, 7)
    }

    func testTheCooldownIsPerOrigin() async throws {
        let world = World()
        let cooldown = RetryCooldown(clock: world.clock)
        _ = await failure { try await self.budget(world, cooldown: cooldown).execute(origin: self.origin, self.script([self.server(429, retryAfter: 30_000)]).call) }
        let value = try await budget(world, cooldown: cooldown).execute(origin: otherOrigin, script([]).call)
        XCTAssertEqual(value, 7)
    }

    func testACooldownIsNotCarriedByANewClientAndIsNotPersisted() async throws {
        let world = World()
        _ = await failure { try await self.budget(world, cooldown: RetryCooldown(clock: world.clock)).execute(origin: self.origin, self.script([self.server(429, retryAfter: 30_000)]).call) }
        // A cold start builds a new cooldown: it knows nothing, and one request is the cost.
        let value = try await budget(world, cooldown: RetryCooldown(clock: world.clock)).execute(origin: origin, script([]).call)
        XCTAssertEqual(value, 7)
    }

    func testExhaustingTheBudgetOnFiveHundredsWithoutARetryAfterStartsNoCooldown() async throws {
        let world = World()
        let cooldown = RetryCooldown(clock: world.clock)
        _ = await failure { try await self.budget(world, cooldown: cooldown).execute(origin: self.origin, self.script([self.server(500), self.server(500), self.server(500)]).call) }
        let again = script([server(500)])
        let value = try await budget(world, cooldown: cooldown).execute(origin: origin, again.call)
        XCTAssertEqual(value, 7)
        let calls = await again.calls.value
        XCTAssertEqual(calls, 2, "a new set of attempts, nothing refused")
    }

    func testARetryAfterThatEndedTheOperationByExhaustionAlsoStartsTheCooldown() async {
        let world = World()
        let cooldown = RetryCooldown(clock: world.clock)
        // Three answers of "wait 2 s": waited twice, the third exhausts the attempts; the server's
        // last word was two seconds, so that is the cooldown.
        let s = script([server(503, retryAfter: 2000), server(503, retryAfter: 2000), server(503, retryAfter: 2000)])
        _ = await failure { try await self.budget(world, cooldown: cooldown).execute(origin: self.origin, s.call) }
        let next = script([])
        let error = await failure { try await self.budget(world, cooldown: cooldown).execute(origin: self.origin, next.call) }
        let sent = await next.calls.value
        XCTAssertEqual(sent, 0)
        XCTAssertEqual(error, .recoverable(.server(status: 503, retryAfterMillis: 2000, attempts: 0, elapsedMillis: 0)))
    }

    func testTheCooldownNeverShortensAnEarlierOneAndLaterOnesExtendIt() async {
        let world = World()
        let cooldown = RetryCooldown(clock: world.clock)
        await cooldown.record(origin: origin, status: 429, retryAfterMillis: 60_000)
        await cooldown.record(origin: origin, status: 503, retryAfterMillis: 5000)
        do {
            try await cooldown.check(origin)
            XCTFail("cooling down")
        } catch {
            XCTAssertEqual(error as? OAuthError, .recoverable(.server(status: 429, retryAfterMillis: 60_000, attempts: 0, elapsedMillis: 0)))
        }
        await cooldown.record(origin: origin, status: 503, retryAfterMillis: 120_000)
        do {
            try await cooldown.check(origin)
            XCTFail("cooling down")
        } catch {
            XCTAssertEqual(error as? OAuthError, .recoverable(.server(status: 503, retryAfterMillis: 120_000, attempts: 0, elapsedMillis: 0)))
        }
    }

    // MARK: A request that is made once

    func testARequestMadeOnceIsNeverRepeatedButRemembersARetryAfter() async {
        let world = World()
        let cooldown = RetryCooldown(clock: world.clock)
        let shared = budget(world, cooldown: cooldown)
        let s = script([server(503, retryAfter: 7000)])
        let error = await failure { try await shared.executeOnce(origin: self.origin, s.call) }
        let calls = await s.calls.value
        XCTAssertEqual(calls, 1)
        XCTAssertEqual(world.delays, [])
        XCTAssertEqual(error, server(503, retryAfter: 7000))
        // The next request to that origin, from any operation, is refused.
        let next = script([])
        let refused = await failure { try await self.budget(world, cooldown: cooldown).execute(origin: self.origin, next.call) }
        let sent = await next.calls.value
        XCTAssertEqual(sent, 0)
        guard case .recoverable(.server(503, 7000, 0, _))? = refused else { return XCTFail("\(String(describing: refused))") }
    }

    func testARequestMadeOnceThatFailsWithoutARetryAfterStartsNoCooldown() async throws {
        let world = World()
        let cooldown = RetryCooldown(clock: world.clock)
        let shared = budget(world, cooldown: cooldown)
        _ = await failure { try await shared.executeOnce(origin: self.origin, self.script([self.server(500)]).call) }
        let value = try await shared.executeOnce(origin: origin, script([]).call)
        XCTAssertEqual(value, 7)
    }

    /// `login()` refuses at its start (where it costs the user nothing); the exchange is sent.
    func testARequestMadeOnceIsNotRefusedByAnActiveCooldown() async throws {
        let world = World()
        let cooldown = RetryCooldown(clock: world.clock)
        await cooldown.record(origin: origin, status: 429, retryAfterMillis: 10_000)
        let s = script([])
        let value = try await budget(world, cooldown: cooldown).executeOnce(origin: origin, s.call)
        XCTAssertEqual(value, 7)
        let calls = await s.calls.value
        XCTAssertEqual(calls, 1)
    }

    // MARK: When the cooldown starts

    /// Only when an operation ENDS because of a Retry-After: one that fits and is then answered
    /// starts nothing.
    func testARetryAfterThatFitsAndThenSucceedsStartsNoCooldown() async throws {
        let world = World()
        let cooldown = RetryCooldown(clock: world.clock)
        let s = script([server(429, retryAfter: 2000)])
        let value = try await budget(world, cooldown: cooldown).execute(origin: origin, s.call)
        XCTAssertEqual(value, 7)
        XCTAssertEqual(world.delays, [2.0])

        let next = script([])
        let again = try await budget(world, cooldown: cooldown).execute(origin: origin, next.call)
        XCTAssertEqual(again, 7)
        let sent = await next.calls.value
        XCTAssertEqual(sent, 1, "nothing was refused: the server was answered, and had said only how long to wait")
    }

    /// A call made while another is waiting out a Retry-After that fits is not refused by it.
    func testACallDuringAWaitThatFitsIsNotRefused() async throws {
        let world = World()
        let cooldown = RetryCooldown(clock: world.clock)
        let gate = Gate()
        let waiting = RetryPolicy.default.newBudget(
            clock: world.clock, random: FixedRandom(fraction: 0), cooldown: cooldown,
            sleep: { _ in await gate.wait() }
        )
        let firstScript = script([server(503, retryAfter: 2000)])
        let origin = self.origin
        let first = Task { try await waiting.execute(origin: origin, firstScript.call) }
        // The first call has failed and is sleeping; a second one, in another operation, arrives.
        try await Task.sleep(nanoseconds: 50_000_000)
        let second = script([])
        let value = try await budget(world, cooldown: cooldown).execute(origin: origin, second.call)
        XCTAssertEqual(value, 7)
        let sent = await second.calls.value
        XCTAssertEqual(sent, 1, "the wait of another call is its own, not a cooldown")
        await gate.open()
        let finished = try await first.value
        XCTAssertEqual(finished, 7)
    }

    func testTheJitterOnARetryAfterNeverPushesItPastTheRoomLeftAndIsNeverNegative() async throws {
        // 19.95 s of 20 s: a tenth would be 1.995 s (capped at 1 s), but only 0.05 s of room is left.
        let tight = World()
        _ = try await budget(tight, fraction: 0.999999).execute(origin: origin, script([server(503, retryAfter: 19_950)]).call)
        XCTAssertEqual(tight.delays.count, 1)
        XCTAssertGreaterThanOrEqual(tight.delays[0], 19.95)
        XCTAssertLessThanOrEqual(tight.delays[0], 20.0)

        // Exactly the room: no jitter at all (the ceiling is zero, not negative), and the wait that
        // consumed the budget leaves nothing for another attempt.
        let exact = World()
        let s = script([server(503, retryAfter: 20_000)])
        let error = await failure { try await self.budget(exact, fraction: 0.999999).execute(origin: self.origin, s.call) }
        XCTAssertEqual(exact.delays, [20.0])
        guard case .recoverable(.server(503, 20_000, 0, _))? = error else { return XCTFail("\(String(describing: error))") }
    }
}
