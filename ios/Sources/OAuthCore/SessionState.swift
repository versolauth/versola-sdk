/// The seven states of `spec/state-machine.md`, and no others. Observable through
/// `OAuthClient.sessionStates()`; the first value a new observer sees is the restored state.
public enum SessionState: String, Sendable, Equatable, CaseIterable {
    case unauthenticated
    case authorizing
    case authenticated
    case refreshing
    case stepUpRequired
    case locked
    case loggingOut
}
