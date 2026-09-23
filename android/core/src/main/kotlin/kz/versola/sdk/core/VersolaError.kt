package kz.versola.sdk.core

/**
 * The four error categories of `spec/errors.md`. The category is the contract: it tells the
 * app what to do, so the type system carries the answer rather than the documentation.
 *
 * Sealed on purpose. A server error code added later is a compile-time break for an
 * exhaustive `when`, never a silent `else` branch.
 *
 * Only the causes, reasons and details reachable from discovery and the browser leg (#5) are
 * modelled here. The token endpoint (#8), the authenticated client (#9) and logout (#10) add
 * their own members, and each addition is expected to show up as an `apiCheck` diff.
 */
public sealed class VersolaError(
    message: String,
    cause: Throwable? = null,
) : Exception(message, cause) {

    /**
     * The SDK already retried within its budget and the operation still failed. Show a
     * transient failure and offer a retry; do not sign the user out.
     *
     * The payload is named `reason` rather than `cause` — the name `spec/errors.md` uses —
     * because [Throwable.cause] already occupies that name with an incompatible type.
     */
    public class Recoverable(
        public val reason: Cause,
        cause: Throwable? = null,
    ) : VersolaError("recoverable: $reason", cause) {

        public sealed interface Cause {
            /** The user dismissed the browser. The pending request is wiped; never retried automatically. */
            public data object UserCancelled : Cause

            /** The OS tore the browser session down. The pending request is kept and may be resumed. */
            public data object SystemCancelled : Cause

            /**
             * A restored pending authorization request was older than
             * [PendingAuthorizationRequest.MAX_AGE_MILLIS]. Authorization codes do not outlive
             * that anyway.
             */
            public data object PendingRequestExpired : Cause

            /** Transport failure, timeout or DNS, surfaced only once the retry budget is exhausted. */
            public data class Network(public val detail: String) : Cause

            /**
             * Under [UnlockPolicy.OnAppUnlock], the storage key's authentication window has
             * elapsed and the refresh token cannot currently be unwrapped. The grant is
             * intact: the app presents a prompt bound to the crypto operation and retries.
             * The access token already in memory stays usable until it expires.
             */
            public data object UnlockRequired : Cause

            /**
             * RFC 9449 §9: a `use_dpop_nonce` challenge answered with the nonce it supplied
             * was challenged again. **Terminating** — `spec/retry-policy.md` allows exactly
             * one nonce retry per origin per operation, because a server that will never be
             * satisfied must not turn into unbounded traffic from a shipped app
             * (scenario 05).
             */
            public data class NonceLoop(public val origin: String) : Cause
        }
    }

    /**
     * The grant is gone. Send the user through `login()` — but the SDK never opens the
     * browser on its own; this is a diagnosis, not a command.
     */
    public class Reauthenticate(
        public val reason: Reason,
    ) : VersolaError("reauthenticate: $reason") {

        public sealed interface Reason {
            /** `access_denied`: the user declined, or the resource owner could not be resolved. */
            public data object AuthorizationDenied : Reason

            /**
             * `login_required`, `consent_required` or `interaction_required`. Only reachable
             * with `prompt=none`.
             */
            public data class InteractionRequired(public val code: String) : Reason

            /**
             * The key protecting stored credentials no longer decrypts them — a biometric
             * enrolment change invalidates it, and that is indistinguishable from tampering.
             * Treated as sign-out, with no error dialog beyond that.
             */
            public data object CredentialsInvalidated : Reason
        }
    }

    /**
     * RFC 9470. The grant is valid; its authentication context is not sufficient for the call
     * edge refused. Not a refresh condition — refreshing here loops against a token that can
     * never satisfy the ACR.
     *
     * Produced by the authenticated client (#9); declared here so the hierarchy an app matches
     * on is complete from the start.
     */
    public class StepUp(
        public val acrValues: List<String>,
        public val maxAge: Long?,
    ) : VersolaError("step-up required: acr_values=$acrValues max_age=$maxAge")

    /**
     * Developer error. Fail loudly in debug builds; catching it in production hides a
     * deployment mistake behind a login screen.
     */
    public class Configuration(
        public val detail: Detail,
        cause: Throwable? = null,
    ) : VersolaError("configuration: $detail", cause) {

        public sealed interface Detail {
            /** `state` on the redirect did not match the persisted value. No token request is made. */
            public data object StateMismatch : Detail

            /**
             * RFC 9207 `iss` did not match the configured issuer, or was absent from a
             * deployment advertising `authorization_response_iss_parameter_supported`.
             * Reported distinctly from [StateMismatch] though both share this category.
             */
            public data class IssuerMismatch(
                public val expected: String,
                public val received: String?,
            ) : Detail

            /** The redirect carried neither `code` nor `error`. */
            public data object MalformedAuthorizationResponse : Detail

            /** The authorization endpoint redirected back with an error in the `Configuration` class. */
            public data class AuthorizationRejected(
                public val code: String,
                public val description: String?,
            ) : Detail

            /** The discovery document omitted a field the SDK cannot proceed without. */
            public data class DiscoveryFieldMissing(public val field: String) : Detail

            /**
             * OpenID Connect Discovery §4.3: the `issuer` in the document must equal the
             * issuer the document was fetched from.
             */
            public data class DiscoveryIssuerMismatch(
                public val configured: String,
                public val advertised: String,
            ) : Detail

            /** The discovery document was not parseable as the metadata document it claims to be. */
            public data class DiscoveryMalformed(public val detail: String) : Detail

            /** `configure()` was given an issuer, client id or redirect URI it cannot use. */
            public data class InvalidConfiguration(public val detail: String) : Detail

            /** No browser on the device can handle the authorization request. */
            public data object NoBrowserAvailable : Detail

            /**
             * `TokenBinding.Dpop(requireHardware = true)` cannot be honoured here: either the
             * device produced only a software-backed key, or the deployment does not
             * advertise DPoP at all. The app asked for a guarantee this pairing cannot give,
             * and it is told so before any authorization request is made (scenario 07).
             */
            public data class HardwareBindingUnavailable(public val detail: String) : Detail
        }
    }
}
