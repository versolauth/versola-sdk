package versola.oauth.core

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject

/**
 * What must survive the app's process being killed while the browser is in the foreground.
 *
 * This is the concrete failure `mobile-demo`'s `pubspec.yaml` records against
 * `flutter_appauth` — AppAuth-Android keeps the pending authorization in the memory of
 * `AuthorizationManagementActivity` — and it is not an edge case on Android. It is persisted
 * *before* the browser opens, because the kill can land between the two.
 *
 * Encrypted at rest through [CredentialKeyProvider]: the `code_verifier` is the other half of
 * the PKCE binding, so it is credential material.
 */
@Serializable
public class PendingAuthorizationRequest
// The full constructor is the module's own; its defaults are what a record persisted before a
// member existed decodes with. The public one below keeps the signature the class was published
// with: the two members added since ([lifetimeMillis], [expectedSubject]) are set
// by a starter or by the flow, never by an app, and a longer public constructor would have broken
// every caller compiled against the old one for nothing.
internal constructor(
    public val state: String,
    public val nonce: String,
    // Readable only inside the core: a store implementation persists this request and hands
    // it back, and the token exchange redeems it, but nothing in between needs to see the
    // other half of the PKCE binding.
    internal val codeVerifier: String,
    public val scopes: List<String>,
    public val redirectUri: String,
    public val acrValues: List<String>,
    public val maxAge: Long?,
    public val createdAtEpochMillis: Long,
    /**
     * What an [AuthorizationStarter] other than the plain PKCE request needs at the exchange,
     * opaque to this module: a back channel that keeps the verifier persists its own artefacts
     * here (the Versola facade's edge flow stores the sealed blob and the endpoints its proofs
     * are signed for). Empty for a request built by [AuthorizationRequest], and for anything
     * persisted before this field existed, which is why it defaults. Copied onto the
     * [AuthorizationGrant] by the validator, byte for byte.
     */
    public val extension: Map<String, String> = emptyMap(),
    /**
     * Whether the redirect must carry RFC 9207 `iss` whatever discovery advertises. A starter
     * whose exchange requires `iss` sets it; the plain request leaves it to the metadata.
     */
    public val issRequired: Boolean = false,
    /**
     * RFC 8707 `resource` values the authorization request carried, repeated on the token
     * request (§2.2) so the token is issued for the audience the user consented to. Empty
     * when there were none, and for anything persisted before this field existed, which is
     * why it defaults.
     */
    public val resources: List<String> = emptyList(),
    /**
     * How long the request lives from [createdAtEpochMillis], when whoever issued it said so: a
     * starter whose back channel seals an expiry of its own (the Versola facade's edge flow, whose
     * blob dies with the lifetime `/native/start` answers) sets it, so that a redirect arriving
     * later is not sent to an exchange that can only be refused. Never longer than
     * [MAX_AGE_MILLIS], which is what a request without one gets, and what a record persisted
     * before this field existed reads as.
     */
    public val lifetimeMillis: Long = MAX_AGE_MILLIS,
    /**
     * The `sub` the sign-in must come back as, for a re-authorization of a session that may not
     * change hands (the Versola facade's step-up). It travels with the request, as [maxAge] does,
     * because the login may be finished by a process that has no caller to ask: the caller was
     * cancelled while the browser was up, or the process died and the redirect reached its
     * successor, and either way the same-user check has to be there. A `sub` is an identifier, not
     * a secret, but it is kept out of [toString] like the rest. Null for a plain sign-in, and for
     * anything persisted before this field existed, which is why it defaults. Copied onto the
     * [AuthorizationGrant] by the validator.
     */
    public val expectedSubject: String? = null,
) {

    /**
     * The constructor apps and starters outside this module see, as it was published. The request
     * lives [MAX_AGE_MILLIS] and expects no particular user; [withLifetime] and the flow change that.
     */
    public constructor(
        state: String,
        nonce: String,
        codeVerifier: String,
        scopes: List<String>,
        redirectUri: String,
        acrValues: List<String>,
        maxAge: Long?,
        createdAtEpochMillis: Long,
        extension: Map<String, String> = emptyMap(),
        issRequired: Boolean = false,
        resources: List<String> = emptyList(),
    ) : this(
        state = state, nonce = nonce, codeVerifier = codeVerifier, scopes = scopes,
        redirectUri = redirectUri, acrValues = acrValues, maxAge = maxAge,
        createdAtEpochMillis = createdAtEpochMillis, extension = extension, issRequired = issRequired,
        resources = resources, lifetimeMillis = MAX_AGE_MILLIS, expectedSubject = null,
    )

    /**
     * This request with the lifetime its issuer gave it, for a starter whose back channel seals an
     * expiry of its own. Capped at [MAX_AGE_MILLIS] where it is read.
     */
    @VersolaInternalApi
    public fun withLifetime(lifetimeMillis: Long): PendingAuthorizationRequest = PendingAuthorizationRequest(
        state = state, nonce = nonce, codeVerifier = codeVerifier, scopes = scopes,
        redirectUri = redirectUri, acrValues = acrValues, maxAge = maxAge,
        createdAtEpochMillis = createdAtEpochMillis, extension = extension, issRequired = issRequired,
        resources = resources, lifetimeMillis = lifetimeMillis, expectedSubject = expectedSubject,
    )

    /** This request bound to [subject], for a flow that learns it after its starter built the request. */
    internal fun expectingSubject(subject: String?): PendingAuthorizationRequest =
        if (subject == null) this else PendingAuthorizationRequest(
            state = state, nonce = nonce, codeVerifier = codeVerifier, scopes = scopes,
            redirectUri = redirectUri, acrValues = acrValues, maxAge = maxAge,
            createdAtEpochMillis = createdAtEpochMillis, extension = extension, issRequired = issRequired,
            resources = resources, lifetimeMillis = lifetimeMillis, expectedSubject = subject,
        )

    private val boundedLifetimeMillis: Long get() = lifetimeMillis.coerceIn(0, MAX_AGE_MILLIS)

    /**
     * A pending request older than its lifetime ([lifetimeMillis], at most [MAX_AGE_MILLIS]) is discarded on restore, leaving
     * `Unauthenticated` — authorization codes do not outlive that anyway. A request that claims to
     * have been created after [nowEpochMillis] by more than [FUTURE_TOLERANCE_MILLIS] is expired too:
     * the wall clock was stepped back since, and "age" computed from it would hold the request, and
     * the wait on its redirect, for as long as the step was long (`AUDIT B12`). A few seconds of NTP
     * correction is not that.
     */
    public fun isExpired(nowEpochMillis: Long): Boolean {
        val age = nowEpochMillis - createdAtEpochMillis
        return age >= boundedLifetimeMillis || age < -FUTURE_TOLERANCE_MILLIS
    }

    /** What is left of the request's life at [nowEpochMillis]: at most its lifetime, at least zero. */
    internal fun remainingMillis(nowEpochMillis: Long): Long =
        (boundedLifetimeMillis - (nowEpochMillis - createdAtEpochMillis)).coerceIn(0, boundedLifetimeMillis)

    /**
     * Neither `state` nor `nonce` nor the verifier: the `state` is what a redirect is matched
     * against and the verifier is the other half of the PKCE binding, and a log line or crash
     * report that carries them gives an observer the half of the binding it lacks.
     */
    override fun toString(): String = "PendingAuthorizationRequest(redacted, createdAt=$createdAtEpochMillis)"

    public companion object {
        /** Ten minutes, per `spec/state-machine.md`. */
        public const val MAX_AGE_MILLIS: Long = 10 * 60 * 1000

        /** How far ahead of the current time a request's creation may lie before the clock is taken to have moved back. */
        internal const val FUTURE_TOLERANCE_MILLIS: Long = 60 * 1000
    }
}

/**
 * Turns a pending request into bytes and back. Lives in `core` rather than in the store so
 * that a store implementation — on any platform, against any key provider — handles opaque
 * bytes only and cannot disagree with another store about the encoding.
 */
@VersolaInternalApi
public object PendingAuthorizationCodec {

    public fun encode(request: PendingAuthorizationRequest): ByteArray =
        discoveryJson.encodeToString(PendingAuthorizationRequest.serializer(), request)
            .toByteArray(Charsets.UTF_8)

    /**
     * A record written before [PendingAuthorizationRequest.extension] existed kept a starter's
     * artefacts as top-level members of its own (the edge flow's `blob` and endpoints). Such a
     * record, unexpired, can be on disk across an update: so when the record carries no
     * `extension`, every unknown string member is kept under its own name in it rather than
     * dropped, and the starter that wrote the old names reads them back. This module knows no
     * names; it only refuses to lose what it did not understand.
     */
    public fun decode(bytes: ByteArray): PendingAuthorizationRequest {
        val text = bytes.toString(Charsets.UTF_8)
        val record = discoveryJson.parseToJsonElement(text).jsonObject
        if (EXTENSION in record) {
            return discoveryJson.decodeFromJsonElement(PendingAuthorizationRequest.serializer(), record)
        }
        val legacy = record.filter { (name, value) ->
            name !in KNOWN_MEMBERS && value is JsonPrimitive && value.isString
        }
        val migrated = JsonObject(record + (EXTENSION to JsonObject(legacy)))
        return discoveryJson.decodeFromJsonElement(PendingAuthorizationRequest.serializer(), migrated)
    }

    private const val EXTENSION = "extension"

    private val KNOWN_MEMBERS = setOf(
        "state", "nonce", "codeVerifier", "scopes", "redirectUri", "acrValues", "maxAge",
        "createdAtEpochMillis", "issRequired", "resources", "lifetimeMillis", "expectedSubject",
    )
}

/**
 * Where the pending request is kept. One slot: a second `login()` while one is outstanding
 * replaces it rather than racing it.
 */
public interface PendingAuthorizationStore {
    public suspend fun save(request: PendingAuthorizationRequest)

    /**
     * Returns null when nothing is pending, and when what was stored can never be read back
     * (a key that is gone for good, bytes that are not a request): that slot is discarded.
     * A failure that says nothing about the slot (a locked key, a keystore fault) throws
     * [VersolaError.Recoverable] and leaves it, and a cancellation propagates as itself.
     */
    public suspend fun load(): PendingAuthorizationRequest?

    public suspend fun clear()
}

/**
 * The seam between what is stored and what protects it.
 *
 * Introduced now rather than later on purpose: retrofitting it forces a storage migration on
 * every installed device, while adding it up front costs an afternoon. #7 ships the
 * hardware-backed provider and the refresh-token store on top of it; #19 adds the PIN
 * provider behind the same two methods.
 */
public interface CredentialKeyProvider {
    public suspend fun wrap(plaintext: ByteArray): ByteArray
    public suspend fun unwrap(blob: ByteArray): ByteArray
}
