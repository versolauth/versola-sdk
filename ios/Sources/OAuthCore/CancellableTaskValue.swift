import Foundation
import os

/// `Task.value` ignores the cancellation of the task that awaits it: a caller that joined a flight
/// (a refresh, a discovery fetch) and was cancelled would stay blocked until the flight ended, however
/// long the network takes. This waits for the same result but returns `CancellationError` at once when
/// the awaiting caller is cancelled, and leaves the flight itself running for the callers still in it
/// and for the persistence that must happen whatever became of the caller (`ios-swift.md`).
package func cancellableValue<T: Sendable>(of task: Task<T, Error>) async throws -> T {
    let waiter = CancellableWaiter<T>()
    return try await withTaskCancellationHandler {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<T, Error>) in
            waiter.install(continuation)
            // Awaits the result in a task of its own, which nothing cancels: the flight's outcome
            // is read once whether or not the caller is still there to take it.
            Task { waiter.finish(await task.result) }
        }
    } onCancel: {
        waiter.finish(.failure(CancellationError()))
    }
}

/// Resumes its continuation exactly once, whichever of the flight's end and the caller's
/// cancellation comes first, including a cancellation that precedes the installation.
private final class CancellableWaiter<T: Sendable>: Sendable {
    private enum State {
        case idle
        case waiting(CheckedContinuation<T, Error>)
        case finished(Result<T, Error>)
        case done
    }

    private let state = OSAllocatedUnfairLock<State>(initialState: .idle)

    func install(_ continuation: CheckedContinuation<T, Error>) {
        let early: Result<T, Error>? = state.withLock { state in
            switch state {
            case .idle:
                state = .waiting(continuation)
                return nil
            case .finished(let result):
                state = .done
                return result
            case .waiting, .done:
                return nil
            }
        }
        if let early { continuation.resume(with: early) }
    }

    func finish(_ result: Result<T, Error>) {
        let continuation: CheckedContinuation<T, Error>? = state.withLock { state in
            switch state {
            case .idle:
                state = .finished(result)
                return nil
            case .waiting(let continuation):
                state = .done
                return continuation
            case .finished, .done:
                return nil
            }
        }
        continuation?.resume(with: result)
    }
}
