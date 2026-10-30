// Type conversion between the Pigeon messages and the SDK's public types. Nothing here decides
// anything: a value the SDK refuses is refused by the SDK, and the refusal is what crosses.
package versola.oauth.flutter

import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import versola.oauth.OAuthConfiguration
import versola.oauth.ProviderEndpoints
import versola.oauth.core.PushedAuthorization
import versola.oauth.core.RetryPolicy
import versola.oauth.core.TokenBinding
import versola.oauth.core.UnlockPolicy
import versola.oauth.core.VersolaError
import versola.oauth.core.VersolaError.Configuration.Detail
import versola.oauth.core.VersolaError.Reauthenticate.Reason
import versola.oauth.core.VersolaError.Recoverable.Cause
import versola.sdk.dpop.KeyAttestation

internal fun ConfigurationMessage.toConfiguration(): OAuthConfiguration =
    OAuthConfiguration(
        issuer = issuer,
        endpoints = endpoints?.let {
            ProviderEndpoints(
                issuer = it.issuer,
                authorizationEndpoint = it.authorizationEndpoint,
                tokenEndpoint = it.tokenEndpoint,
                jwksUri = it.jwksUri,
                userinfoEndpoint = it.userinfoEndpoint,
                revocationEndpoint = it.revocationEndpoint,
                endSessionEndpoint = it.endSessionEndpoint,
                pushedAuthorizationRequestEndpoint = it.pushedAuthorizationRequestEndpoint,
                idTokenSigningAlgValuesSupported = it.idTokenSigningAlgValuesSupported,
            )
        },
        clientId = clientId,
        redirectUri = redirectUri,
        postLogoutRedirectUri = postLogoutRedirectUri,
        scopes = scopes.toSet(),
        tokenBinding = when (tokenBinding) {
            TokenBindingMessage.BEARER -> TokenBinding.Bearer
            TokenBindingMessage.DPOP -> TokenBinding.Dpop(requireHardware = false)
            TokenBindingMessage.DPOP_REQUIRE_HARDWARE -> TokenBinding.Dpop(requireHardware = true)
        },
        pushedAuthorization = when (pushedAuthorization) {
            PushedAuthorizationMessage.NEVER -> PushedAuthorization.Never
            PushedAuthorizationMessage.WHEN_ADVERTISED -> PushedAuthorization.WhenAdvertised
            PushedAuthorizationMessage.REQUIRED -> PushedAuthorization.Required
        },
        protectedOrigins = protectedOrigins.toSet(),
        endSessionEndpoint = endSessionEndpoint,
        retryPolicy = retryPolicy?.let {
            RetryPolicy(
                maxAttemptsPerOrigin = it.maxAttemptsPerOrigin.toInt(),
                maxTotalAttempts = it.maxTotalAttempts.toInt(),
                initialBackoff = it.initialBackoffMillis.milliseconds,
                backoffMultiplier = it.backoffMultiplier,
                maxBackoff = it.maxBackoffMillis.milliseconds,
                totalBudget = it.totalBudgetMillis.milliseconds,
            )
        } ?: RetryPolicy.Default,
        unlockPolicy = when (unlockPolicy) {
            UnlockPolicyMessage.NONE -> UnlockPolicy.None
            UnlockPolicyMessage.ON_APP_UNLOCK -> UnlockPolicy.OnAppUnlock
        },
        clockSkewTolerance = clockSkewToleranceSeconds.seconds,
    )

internal fun KeyAttestation.toWireName(): String = when (this) {
    KeyAttestation.StrongBox -> "strongBox"
    KeyAttestation.TrustedEnvironment -> "trustedEnvironment"
    KeyAttestation.Software -> "software"
}

/**
 * Flattens the taxonomy for the wire. `category` is the contract; `kind` is the case name in
 * the spelling Dart's enums use, so the sealed hierarchy is rebuilt case for case. The text
 * is the SDK's own message, which never carries a credential (`security.md`).
 */
internal fun VersolaError.toMessage(): ErrorMessage = when (this) {
    is VersolaError.Recoverable -> when (val c = reason) {
        Cause.UserCancelled -> recoverable("userCancelled")
        Cause.SystemCancelled -> recoverable("systemCancelled")
        Cause.PendingRequestExpired -> recoverable("pendingRequestExpired")
        is Cause.Network -> recoverable("network").copy(detail = c.detail, attempts = c.attempts.toLong(), elapsedMillis = c.elapsedMillis)
        is Cause.Server -> recoverable("server").copy(
            status = c.status.toLong(),
            retryAfterMillis = c.retryAfterMillis,
            attempts = c.attempts.toLong(),
            elapsedMillis = c.elapsedMillis,
        )
        Cause.UnlockRequired -> recoverable("unlockRequired")
        is Cause.NonceLoop -> recoverable("nonceLoop").copy(origin = c.origin)
    }
    is VersolaError.Reauthenticate -> when (val r = reason) {
        Reason.AuthorizationDenied -> reauthenticate("authorizationDenied")
        is Reason.InteractionRequired -> reauthenticate("interactionRequired").copy(code = r.code)
        Reason.CredentialsInvalidated -> reauthenticate("credentialsInvalidated")
        Reason.GrantRejected -> reauthenticate("grantRejected")
        Reason.SessionRejected -> reauthenticate("sessionRejected")
        Reason.SessionExpired -> reauthenticate("sessionExpired")
    }
    is VersolaError.StepUp -> ErrorMessage(
        category = ErrorCategoryMessage.STEP_UP, kind = "stepUp", message = message.orEmpty(),
        acrValues = acrValues, maxAge = maxAge,
    )
    is VersolaError.Configuration -> when (val d = detail) {
        Detail.StateMismatch -> configuration("stateMismatch")
        is Detail.IssuerMismatch -> configuration("issuerMismatch").copy(expected = d.expected, received = d.received)
        Detail.MalformedAuthorizationResponse -> configuration("malformedAuthorizationResponse")
        is Detail.AuthorizationRejected -> configuration("authorizationRejected").copy(code = d.code, errorDescription = d.description)
        is Detail.TokenRequestRejected -> configuration("tokenRequestRejected").copy(code = d.code, errorDescription = d.description)
        is Detail.TokenResponseMalformed -> configuration("tokenResponseMalformed").copy(detail = d.detail)
        is Detail.DiscoveryFieldMissing -> configuration("discoveryFieldMissing").copy(field = d.field)
        is Detail.DiscoveryIssuerMismatch -> configuration("discoveryIssuerMismatch").copy(expected = d.configured, received = d.advertised)
        is Detail.DiscoveryMalformed -> configuration("discoveryMalformed").copy(detail = d.detail)
        is Detail.InvalidConfiguration -> configuration("invalidConfiguration").copy(detail = d.detail)
        Detail.NoBrowserAvailable -> configuration("noBrowserAvailable")
        is Detail.IdTokenRejected -> configuration("idTokenRejected").copy(idTokenRejection = d.reason.name.replaceFirstChar(Char::lowercase))
        is Detail.UserInfoRejected -> configuration("userInfoRejected").copy(detail = d.detail)
        is Detail.ProviderUnsupported -> configuration("providerUnsupported").copy(capability = d.capability)
        is Detail.HardwareBindingUnavailable -> configuration("hardwareBindingUnavailable").copy(detail = d.detail)
        // A facade's own back-channel case; the generic facade produces none. Dart keeps the
        // category and names the class (`ConfigurationDetail.unknown` with the text).
        is Detail.Extension -> configuration(d::class.simpleName ?: "extension")
    }
}

/**
 * What crosses for an exception that is not a `VersolaError`: a `Configuration` naming only the
 * class. The exception's message and stack never leave native code (`flutter.md`, "No secret in
 * a `PlatformException` message").
 */
internal fun Throwable.toErrorMessage(): ErrorMessage = (this as? VersolaError)?.toMessage()
    ?: ErrorMessage(
        category = ErrorCategoryMessage.CONFIGURATION,
        kind = "invalidConfiguration",
        message = "configuration: unexpected ${this::class.simpleName}",
        detail = "unexpected ${this::class.simpleName}",
    )

private fun VersolaError.recoverable(kind: String) =
    ErrorMessage(category = ErrorCategoryMessage.RECOVERABLE, kind = kind, message = message.orEmpty())

private fun VersolaError.reauthenticate(kind: String) =
    ErrorMessage(category = ErrorCategoryMessage.REAUTHENTICATE, kind = kind, message = message.orEmpty())

private fun VersolaError.configuration(kind: String) =
    ErrorMessage(category = ErrorCategoryMessage.CONFIGURATION, kind = kind, message = message.orEmpty())
