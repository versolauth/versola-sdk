// Type conversion between the Pigeon messages and the SDK's public types. Nothing here decides
// anything: a value the SDK refuses is refused by the SDK, and the refusal is what crosses.
package versola.sdk.flutter

import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import okhttp3.Headers
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import versola.oauth.core.AuthorizationParameters
import versola.oauth.core.RetryPolicy
import versola.oauth.core.UnlockPolicy
import versola.oauth.core.VersolaError
import versola.oauth.core.VersolaError.Configuration.Detail
import versola.oauth.core.VersolaError.Reauthenticate.Reason
import versola.oauth.core.VersolaError.Recoverable.Cause
import versola.oauth.core.SessionState
import versola.sdk.LoginOptions
import versola.sdk.VersolaConfiguration
import versola.sdk.dpop.KeyAttestation

internal fun VersolaConfigurationMessage.toConfiguration(): VersolaConfiguration {
    val unlock = when (unlockPolicy) {
        VersolaUnlockPolicyMessage.NONE -> UnlockPolicy.None
        VersolaUnlockPolicyMessage.ON_APP_UNLOCK -> UnlockPolicy.OnAppUnlock
    }
    val retry = retryPolicy?.let {
        RetryPolicy(
            maxAttemptsPerOrigin = it.maxAttemptsPerOrigin.toInt(),
            maxTotalAttempts = it.maxTotalAttempts.toInt(),
            initialBackoff = it.initialBackoffMillis.milliseconds,
            backoffMultiplier = it.backoffMultiplier,
            maxBackoff = it.maxBackoffMillis.milliseconds,
            totalBudget = it.totalBudgetMillis.milliseconds,
        )
    } ?: RetryPolicy.Default
    val skew = clockSkewToleranceSeconds.seconds
    // The issuer's default is the SDK's (`issuer = edgeUrl`), reached by not passing one: the glue
    // does not restate it, so a change of that default cannot leave the two disagreeing.
    return if (issuer == null) {
        VersolaConfiguration(
            edgeUrl = edgeUrl, clientId = clientId, redirectUri = redirectUri,
            postLogoutRedirectUri = postLogoutRedirectUri, requireHardwareKey = requireHardwareKey,
            unlockPolicy = unlock, retryPolicy = retry, clockSkewTolerance = skew,
        )
    } else {
        VersolaConfiguration(
            edgeUrl = edgeUrl, clientId = clientId, redirectUri = redirectUri, issuer = issuer,
            postLogoutRedirectUri = postLogoutRedirectUri, requireHardwareKey = requireHardwareKey,
            unlockPolicy = unlock, retryPolicy = retry, clockSkewTolerance = skew,
        )
    }
}

internal fun VersolaLoginOptionsMessage.toLoginOptions(): LoginOptions = LoginOptions(
    scopes = scopes.toSet(),
    acrValues = acrValues,
    maxAge = maxAge,
    prompt = prompt?.let {
        when (it) {
            VersolaPromptMessage.NONE -> AuthorizationParameters.Prompt.None
            VersolaPromptMessage.LOGIN -> AuthorizationParameters.Prompt.Login
            VersolaPromptMessage.CONSENT -> AuthorizationParameters.Prompt.Consent
            VersolaPromptMessage.SELECT_ACCOUNT -> AuthorizationParameters.Prompt.SelectAccount
            VersolaPromptMessage.CREATE -> AuthorizationParameters.Prompt.Create
        }
    },
    loginHint = loginHint,
    uiLocales = uiLocales,
    resources = resources,
    claims = claims,
    authorizationDetails = authorizationDetails,
    ephemeralBrowser = ephemeralBrowser,
)

internal fun SessionState.toMessage(): VersolaSessionStateMessage = when (this) {
    SessionState.Unauthenticated -> VersolaSessionStateMessage.UNAUTHENTICATED
    SessionState.Authorizing -> VersolaSessionStateMessage.AUTHORIZING
    SessionState.Authenticated -> VersolaSessionStateMessage.AUTHENTICATED
    SessionState.Refreshing -> VersolaSessionStateMessage.REFRESHING
    SessionState.StepUpRequired -> VersolaSessionStateMessage.STEP_UP_REQUIRED
    SessionState.Locked -> VersolaSessionStateMessage.LOCKED
    SessionState.LoggingOut -> VersolaSessionStateMessage.LOGGING_OUT
}

internal fun KeyAttestation.toWireName(): String = when (this) {
    KeyAttestation.StrongBox -> "strongBox"
    KeyAttestation.TrustedEnvironment -> "trustedEnvironment"
    KeyAttestation.Software -> "software"
}

/**
 * Flattens the taxonomy for the wire. `category` is the contract; `kind` is the case name in
 * the spelling Dart's enums use, so the sealed hierarchy is rebuilt case for case. The text
 * is the SDK's own message, which never carries a credential (`security.md`). `sdkCode` is the
 * error's stable `code` (`spec/errors.md`, "Stable codes"), distinct from `code`, which is the
 * provider's OAuth error code.
 */
internal fun VersolaError.toMessage(): VersolaErrorMessage = toKindMessage().copy(sdkCode = code)

private fun VersolaError.toKindMessage(): VersolaErrorMessage = when (this) {
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
        Cause.AccountMismatch -> recoverable("accountMismatch")
    }
    is VersolaError.Reauthenticate -> when (val r = reason) {
        Reason.AuthorizationDenied -> reauthenticate("authorizationDenied")
        is Reason.InteractionRequired -> reauthenticate("interactionRequired").copy(code = r.code)
        Reason.CredentialsInvalidated -> reauthenticate("credentialsInvalidated")
        Reason.GrantRejected -> reauthenticate("grantRejected")
        Reason.SessionRejected -> reauthenticate("sessionRejected")
        Reason.SessionExpired -> reauthenticate("sessionExpired")
    }
    is VersolaError.StepUp -> VersolaErrorMessage(
        category = VersolaErrorCategoryMessage.STEP_UP, kind = "stepUp", message = message.orEmpty(),
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
        // A facade's own detail (`EdgeClientUnknown` is the Versola facade's): Dart has no name for
        // it, so it is `unknown` with the snake_case name, never a guessed real case. The stable
        // code (`configuration.edge_client_unknown`) travels in `sdkCode`, set by `toMessage`.
        is Detail.Extension -> configuration("unknown").copy(detail = d.name)
    }
}

/**
 * What crosses for an exception that is not a `VersolaError`: a `Configuration` naming only the
 * class. The exception's message and stack never leave native code (`flutter.md`, "No secret in
 * a `PlatformException` message").
 */
internal fun Throwable.toErrorMessage(): VersolaErrorMessage = (this as? VersolaError)?.toMessage()
    ?: VersolaErrorMessage(
        category = VersolaErrorCategoryMessage.CONFIGURATION,
        kind = "invalidConfiguration",
        message = "configuration: unexpected ${this::class.simpleName}",
        detail = "unexpected ${this::class.simpleName}",
        sdkCode = "configuration.invalid_configuration",
    )

private fun VersolaError.recoverable(kind: String) =
    VersolaErrorMessage(category = VersolaErrorCategoryMessage.RECOVERABLE, kind = kind, message = message.orEmpty())

private fun VersolaError.reauthenticate(kind: String) =
    VersolaErrorMessage(category = VersolaErrorCategoryMessage.REAUTHENTICATE, kind = kind, message = message.orEmpty())

private fun VersolaError.configuration(kind: String) =
    VersolaErrorMessage(category = VersolaErrorCategoryMessage.CONFIGURATION, kind = kind, message = message.orEmpty())

// MARK: HTTP (`Versola.call`)

/** OkHttp refuses these methods without a body, where Dart's `package:http` allows an empty one. */
private val METHODS_NEEDING_A_BODY = setOf("POST", "PUT", "PATCH", "PROPPATCH", "REPORT")
private val METHODS_WITHOUT_A_BODY = setOf("GET", "HEAD")

private fun invalidRequest(): VersolaError.Configuration =
    // A fixed text, not OkHttp's: its messages quote the offending header value, which can be a credential.
    VersolaError.Configuration(Detail.InvalidConfiguration("the request is not a valid HTTP request (an absolute http(s) URL, a method, headers)"))

/**
 * The request Dart described, as an OkHttp request, and nothing else: no header is added,
 * removed or rewritten here (the SDK's client replaces `Authorization` and `DPoP` on the edge and
 * leaves every other origin untouched). Headers are added in order, so a repeated name keeps its
 * values. Anything OkHttp or the rules below refuse is `InvalidConfiguration` with a fixed text.
 */
internal fun VersolaHttpRequestMessage.toRequest(): Request {
    val parsed = url.toHttpUrlOrNull() ?: throw invalidRequest()
    val payload = body?.takeIf { it.isNotEmpty() }
    val requestBody = when {
        method in METHODS_WITHOUT_A_BODY -> if (payload == null) null else throw invalidRequest()
        payload != null -> payload.toRequestBody()
        method in METHODS_NEEDING_A_BODY -> ByteArray(0).toRequestBody()
        else -> null
    }
    return try {
        val sent = Headers.Builder().apply { headers.forEach { add(it.name, it.value) } }.build()
        Request.Builder().url(parsed).headers(sent).method(method, requestBody).build()
    } catch (e: IllegalArgumentException) {
        throw invalidRequest()
    }
}

/** The whole response, body included: the bridge carries bytes. Reads the body, so it runs off the main thread. */
internal fun Response.toMessage(): VersolaHttpResponseMessage = VersolaHttpResponseMessage(
    status = code.toLong(),
    // HTTP/2 has no reason phrase; OkHttp reports an empty one.
    reasonPhrase = message.ifEmpty { null },
    headers = (0 until headers.size).map { VersolaHttpHeaderMessage(name = headers.name(it), value = headers.value(it)) },
    body = body.bytes(),
)
