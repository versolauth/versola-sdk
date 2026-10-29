import Foundation

/// Hosts the session state every part of the machine shares and fans it out to observers.
///
/// `AsyncStream` is single-consumer: two `for await` loops over one stream steal elements from
/// each other. So `stream()` makes a new stream per call, and the hub keeps one continuation per
/// live stream, removed when the observer stops listening. Each stream starts with the current
/// state, which is what lets an app that subscribes late (after a cold start restored
/// `authorizing`, say) see the true state rather than wait for the next change.
package actor SessionStateHub {
    private var state: SessionState
    private var continuations: [UUID: AsyncStream<SessionState>.Continuation] = [:]

    package init(initial: SessionState = .unauthenticated) {
        state = initial
    }

    /// The state right now.
    package var current: SessionState { state }

    /// Publishes `next` to every observer. A repeat of the current state is not re-published:
    /// observers drive UI, and a redundant element would redraw it for nothing.
    package func set(_ next: SessionState) {
        guard next != state else { return }
        state = next
        for continuation in continuations.values { continuation.yield(next) }
    }

    /// A stream of the current state followed by every change. Unbounded buffering: a slow
    /// observer must not miss a transition, and the machine has seven states, so the backlog is
    /// bounded by how fast the session can change.
    package func stream() -> AsyncStream<SessionState> {
        let id = UUID()
        var captured: AsyncStream<SessionState>.Continuation?
        let stream = AsyncStream<SessionState>(bufferingPolicy: .unbounded) { captured = $0 }
        guard let continuation = captured else { return stream }
        continuation.yield(state)
        continuations[id] = continuation
        // The termination handler runs on whatever thread ends the stream, so it hops back
        // onto the actor to touch the dictionary.
        continuation.onTermination = { [weak self] _ in
            Task { await self?.remove(id) }
        }
        return stream
    }

    /// How many streams are being listened to; tests assert a finished one is gone.
    var observerCount: Int { continuations.count }

    private func remove(_ id: UUID) {
        continuations[id] = nil
    }
}
