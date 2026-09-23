package kz.versola.sdk.core

/**
 * The seven states of `spec/state-machine.md`, and no others: platform-specific states are
 * not permitted, because the machine is normative across Android, iOS and Flutter.
 *
 * A sealed interface rather than an enum so a state can gain a payload later — `StepUpRequired`
 * carrying its challenge, say — without changing the kind of the type every app matches on.
 *
 * `Refreshing`, `StepUpRequired`, `Locked` and `LoggingOut` are sub-states of holding a grant:
 * the app is not signed out while in them and UI must not treat them as such.
 */
public sealed interface SessionState {

    /** No usable grant. `login()` is the only meaningful call. */
    public data object Unauthenticated : SessionState

    /** An authorization request is outstanding: the browser is open, or the app was killed while it was. */
    public data object Authorizing : SessionState

    /** A refresh token is held and an access token is available or derivable. */
    public data object Authenticated : SessionState

    /** A token request is in flight. Concurrent callers coalesce onto it rather than each entering this state. */
    public data object Refreshing : SessionState

    /** Edge refused a call with `insufficient_user_authentication`. The grant is valid; its ACR is not sufficient. */
    public data object StepUpRequired : SessionState

    /** Credentials are present but the key protecting them needs user authentication. */
    public data object Locked : SessionState

    /** RP-initiated logout is in flight. */
    public data object LoggingOut : SessionState
}
