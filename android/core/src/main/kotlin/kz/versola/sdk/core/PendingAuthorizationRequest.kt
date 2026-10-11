package kz.versola.sdk.core

import kotlinx.serialization.Serializable

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
     * Under [BackChannel.Edge]: the sealed blob `/native/start` issued, which the exchange
     * presents at `/native/complete`. It stands in for the `code_verifier`, which edge sealed
     * inside it and the device never sees — [codeVerifier] is empty in that mode. Null for a
     * request started directly against auth, and for anything persisted before this field
     * existed, which is why every field below defaults.
     */
    public val blob: String? = null,
    /** The `htu` the exchange's proof is signed for; see [NativeStart.tokenEndpoint]. */
    public val tokenEndpoint: String? = null,
    public val revocationEndpoint: String? = null,
) {

    /** Whether this request was started through edge and must be completed there. */
    public val viaEdge: Boolean get() = blob != null

    /**
     * A pending request older than [MAX_AGE_MILLIS] is discarded on restore, leaving
     * `Unauthenticated` — authorization codes do not outlive that anyway.
     */
    public fun isExpired(nowEpochMillis: Long): Boolean =
        nowEpochMillis - createdAtEpochMillis >= MAX_AGE_MILLIS

    override fun toString(): String = "PendingAuthorizationRequest(state=$state, createdAt=$createdAtEpochMillis)"

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

    public fun decode(bytes: ByteArray): PendingAuthorizationRequest =
        discoveryJson.decodeFromString(
            PendingAuthorizationRequest.serializer(),
            bytes.toString(Charsets.UTF_8),
        )
}

/**
 * Where the pending request is kept. One slot: a second `login()` while one is outstanding
 * replaces it rather than racing it.
 */
public interface PendingAuthorizationStore {
    public suspend fun save(request: PendingAuthorizationRequest)

    /** Returns null when nothing is pending, and when what was stored cannot be read back. */
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
