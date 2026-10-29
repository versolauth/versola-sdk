import XCTest
@testable import OAuthCore

final class SessionStateHubTests: XCTestCase {
    func testAStreamStartsWithTheCurrentStateThenEveryChange() async {
        let hub = SessionStateHub(initial: .authorizing)
        let stream = await hub.stream()
        var iterator = stream.makeAsyncIterator()
        let first = await iterator.next()
        XCTAssertEqual(first, .authorizing)
        await hub.set(.authenticated)
        await hub.set(.refreshing)
        let second = await iterator.next()
        let third = await iterator.next()
        XCTAssertEqual(second, .authenticated)
        XCTAssertEqual(third, .refreshing)
    }

    func testTwoObserversEachSeeTheCurrentStateAndTheChanges() async {
        let hub = SessionStateHub()
        await hub.set(.authenticated)
        var a = await hub.stream().makeAsyncIterator()
        var b = await hub.stream().makeAsyncIterator()
        let aFirst = await a.next()
        let bFirst = await b.next()
        XCTAssertEqual(aFirst, .authenticated)
        XCTAssertEqual(bFirst, .authenticated)
        await hub.set(.loggingOut)
        await hub.set(.unauthenticated)
        let aSeen = [await a.next(), await a.next()]
        let bSeen = [await b.next(), await b.next()]
        XCTAssertEqual(aSeen, [.loggingOut, .unauthenticated])
        XCTAssertEqual(bSeen, [.loggingOut, .unauthenticated])
    }

    func testCurrentReflectsTheLastSet() async {
        let hub = SessionStateHub()
        var current = await hub.current
        XCTAssertEqual(current, .unauthenticated)
        await hub.set(.locked)
        current = await hub.current
        XCTAssertEqual(current, .locked)
    }

    func testARepeatedStateIsNotPublishedAgain() async {
        let hub = SessionStateHub()
        var iterator = await hub.stream().makeAsyncIterator()
        _ = await iterator.next()
        await hub.set(.unauthenticated)
        await hub.set(.authorizing)
        let next = await iterator.next()
        XCTAssertEqual(next, .authorizing)
    }

    func testATerminatedStreamIsRemovedAndTheOthersKeepWorking() async {
        let hub = SessionStateHub()
        var survivor = await hub.stream().makeAsyncIterator()
        _ = await survivor.next()
        do {
            var short = await hub.stream().makeAsyncIterator()
            _ = await short.next()
            let during = await hub.observerCount
            XCTAssertEqual(during, 2)
        }
        await AuthzKit.waitUntil("the finished stream is removed") { await hub.observerCount == 1 }
        await hub.set(.authorizing)
        let seen = await survivor.next()
        XCTAssertEqual(seen, .authorizing)
    }

    func testACancelledObserverTaskIsRemoved() async {
        let hub = SessionStateHub()
        let stream = await hub.stream()
        let task = Task { for await _ in stream {} }
        await AuthzKit.waitUntil("the observer is registered") { await hub.observerCount == 1 }
        task.cancel()
        await task.value
        await AuthzKit.waitUntil("the cancelled observer is removed") { await hub.observerCount == 0 }
    }
}
