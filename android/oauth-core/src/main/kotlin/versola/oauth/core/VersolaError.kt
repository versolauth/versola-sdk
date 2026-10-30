package versola.oauth.core

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

            /**
             * Transport failure, timeout or DNS, surfaced only once the retry budget is
             * exhausted.
             *
             * [attempts] and [elapsedMillis] are how an integrator tells a ceiling that was
             * reached from a single request that failed: the same message carries both
             * otherwise. They describe the operation rather than this request — the default
             * of one attempt is the failure of a call made outside any [RetryBudget], which
             * is the only attempt there was.
             */
            public data class Network(
                public val detail: String,
                public val attempts: Int = 1,
                public val elapsedMillis: Long = 0,
            ) : Cause

            /**
             * A provider answered, and the answer kept the operation from finishing: 408, 429,
             * a 5xx, or a status the operation had no use for. Surfaced once the retry budget
             * is exhausted, at once when [retryAfterMillis] does not fit what is left of it, at
             * once for a status a repeat cannot help (501, 505, a 404 where a document was
             * expected), and at once while a `Retry-After` the server gave is still running
             * (`spec/retry-policy.md`, cooldown).
             *
             * [status] is the last one seen. A 429 and a 5xx are told apart here, not by
             * category: both are `Recoverable`. [retryAfterMillis] is the `Retry-After` of a 429
             * or 503, parsed and saturated at one day, and null when there was none or it was
             * unreadable; an app that gets one does not repeat before it. [attempts] and
             * [elapsedMillis] are those of the operation, as in [Network]; [attempts] is 0 when
             * nothing was sent because a cooldown was running.
             */
            public data class Server(
                public val status: Int,
                public val retryAfterMillis: Long? = null,
                public val attempts: Int = 1,
                public val elapsedMillis: Long = 0,
            ) : Cause

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

            /**
             * The token endpoint answered `invalid_grant`. Code expiry, PKCE mismatch,
             * redirect mismatch, refresh replay, family revocation and DPoP key mismatch all
             * arrive as this one code, with an identical body, by design — so there is one
             * reason here rather than six guesses.
             *
             * **Never retried.** A retry loop on `invalid_grant` against a rotating-refresh
             * deployment is how clients silently log users out.
             */
            public data object GrantRejected : Reason

            /**
             * A call through the authenticated client was refused with a bare 401, and a
             * refresh did not change that (`spec/errors.md`, edge table).
             *
             * Distinct from [GrantRejected], which is the token endpoint's own
             * `invalid_grant`: here the token endpoint answered *successfully* and the
             * resource server refused the token it issued anyway. Same instruction to the
             * app, different fact about which server said what — and reusing the other
             * reason would send an integrator reading a rotation bug into a resource-server
             * audience or revocation problem.
             */
            public data object SessionRejected : Reason

            /**
             * The access token expired and the provider issued no refresh token to spend
             * (`spec/state-machine.md`, "no refresh token"). Nothing was retried and no token
             * request was made; the session is over and the user signs in again.
             */
            public data object SessionExpired : Reason
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

            /**
             * The token endpoint refused the request for a reason no user action fixes:
             * `invalid_request`, `invalid_client`, `unauthorized_client`,
             * `unsupported_grant_type`, `invalid_scope`, `invalid_target`,
             * `invalid_authorization_details` — or a code this SDK does not know, which is a
             * deployment it cannot reason about rather than a silent success.
             *
             * `invalid_grant` is deliberately not here: it is the one token-endpoint code
             * that means the user must sign in again.
             */
            public data class TokenRequestRejected(
                public val code: String,
                public val description: String?,
            ) : Detail

            /**
             * The token endpoint answered 2xx with something that is not a token response —
             * unparseable, or missing `access_token`. A deployment fault rather than a
             * transient one: the next attempt returns the same thing.
             */
            public data class TokenResponseMalformed(public val detail: String) : Detail

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
             * The ID token failed validation (OpenID Connect Core 3.1.3.7). Nothing was
             * persisted and the session settled where it was before `login()`. Every reason
             * is a deployment mistake (issuer, algorithm, audience, clock) or an attack, and
             * the user trying again fixes neither, which is why this is `Configuration`
             * (`spec/errors.md`).
             */
            public data class IdTokenRejected(public val reason: IdTokenRejection) : Detail

            /**
             * The UserInfo response is not about the user the ID token names, or a signed
             * UserInfo response does not verify (OpenID Connect Core 5.3.2).
             */
            public data class UserInfoRejected(public val detail: String) : Detail

            /**
             * The configuration needs a capability the provider does not advertise: DPoP
             * required but not offered, pushed authorization required but no endpoint, a
             * UserInfo call without an endpoint, `S256` absent from
             * `code_challenge_methods_supported`. Raised at the first operation that needs the
             * capability, never by a silent downgrade.
             */
            public data class ProviderUnsupported(public val capability: String) : Detail

            /**
             * A case a facade adds for a back channel of its own (the Versola facade's edge
             * errors). This module produces none; an exhaustive `when` handles the class as
             * one branch, and the facade documents its subclasses.
             */
            public abstract class Extension : Detail

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

/** Why an ID token was refused; one value per check of OpenID Connect Core 3.1.3.7. */
public enum class IdTokenRejection {
    /** The signature does not verify against any key at `jwks_uri`, after one refetch. */
    Signature,

    /** `alg` is outside the closed asymmetric set, or not advertised by the provider. */
    Algorithm,

    /** `iss` is not the issuer, byte for byte. */
    Issuer,

    /** `aud` does not contain the client id, or several audiences without a matching `azp`. */
    Audience,

    /** `exp` is in the past beyond the clock-skew tolerance. */
    Expired,

    /** `iat` is missing or too far from now. */
    IssuedAt,

    /** `nonce` is missing or not the one the request carried. */
    Nonce,

    /** `auth_time` is missing under `max_age`, older than it, or moved backwards on refresh. */
    AuthTime,

    /** Not a JWS, not JSON, a required claim missing or of the wrong type. */
    Malformed,

    /** `at_hash` is present and does not match the access token. */
    AccessTokenHash,
}
