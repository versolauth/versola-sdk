package kz.versola.sdk.core

/**
 * Whether the key protecting stored credentials requires a recent user authentication.
 *
 * One knob, and it moves the *storage* key only: the DPoP key is never gated, because it signs
 * a proof on every request and Android fails biometric authentication outside the foreground
 * (#1 §4). Encryption at rest and user authentication are different mechanisms.
 *
 * An enum rather than a sealed class because there is nothing to carry: the window is fixed at
 * [UNLOCK_WINDOW_SECONDS] across platforms, and a PIN-derived key (#19) is a different
 * [CredentialKeyProvider] rather than a different policy.
 *
 * Two tiers, not three. `spec/state-machine.md` records why a per-call tier is not offered and
 * why `StepUpRequired` is where a per-operation requirement belongs.
 */
public enum class UnlockPolicy {
    /**
     * The key is usable whenever the app is. Credentials are still encrypted at rest; nothing
     * prompts, and refresh works in the background.
     */
    None,

    /**
     * The key is authorized for [UNLOCK_WINDOW_SECONDS] after any matching OS authentication —
     * including the device unlock that preceded the app being opened, which is why a typical
     * session raises no prompt of the SDK's own.
     *
     * Once the window elapses, unwrapping fails with
     * [VersolaError.Recoverable.Cause.UnlockRequired] and the session enters
     * [SessionState.Locked]. The app presents the prompt and retries; the SDK holds no
     * `Activity` and does not present one itself.
     */
    OnAppUnlock,

    ;

    public companion object {
        /**
         * iOS caps `touchIDAuthenticationAllowableReuseDuration` at five minutes. Android
         * permits longer, and matching the stricter platform keeps one state machine rather
         * than two.
         */
        public const val UNLOCK_WINDOW_SECONDS: Int = 300
    }
}
