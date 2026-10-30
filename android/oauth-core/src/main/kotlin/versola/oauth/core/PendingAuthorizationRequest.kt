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
public class PendingAuthorizationRequest public constructor(
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
) {

    /**
     * A pending request older than [MAX_AGE_MILLIS] is discarded on restore, leaving
     * `Unauthenticated` — authorization codes do not outlive that anyway.
     */
    public fun isExpired(nowEpochMillis: Long): Boolean =
        nowEpochMillis - createdAtEpochMillis >= MAX_AGE_MILLIS

    /**
     * Neither `state` nor `nonce` nor the verifier: the `state` is what a redirect is matched
     * against and the verifier is the other half of the PKCE binding, and a log line or crash
     * report that carries them gives an observer the half of the binding it lacks.
     */
    override fun toString(): String = "PendingAuthorizationRequest(redacted, createdAt=$createdAtEpochMillis)"

    public companion object {
        /** Ten minutes, per `spec/state-machine.md`. */
        public const val MAX_AGE_MILLIS: Long = 10 * 60 * 1000
    }
}

/**
 * Turns a pending request into bytes and back. Lives in `core` rather than in the store so
 * that a store implementation — on any platform, against any key provider — handles opaque
 * bytes only and cannot disagree with another store about the encoding.
 */
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
        "createdAtEpochMillis", "issRequired", "resources",
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
