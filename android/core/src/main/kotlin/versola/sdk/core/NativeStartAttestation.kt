package versola.sdk.core

import java.security.MessageDigest
import java.util.Base64
import versola.oauth.core.VersolaInternalApi

/**
 * What the app proves about itself on `POST /native/start`, as the extra form fields the request
 * carries (`spec/server-dependencies.md`, "App attestation on `/native/start`"). Evidence, not a
 * permission: an implementation returns what the device has and nothing is decided here -- an
 * empty list is a device with no evidence to give, and edge's policy for the client decides
 * whether a request without any is acceptable.
 *
 * A separate seam from the proof source because the evidence is about the *key* and is read once
 * per start, while a proof is minted per request; and internal because nothing about it is a
 * promise to an app yet.
 */
@VersolaInternalApi
public fun interface NativeStartAttestation {
    public suspend fun fields(): List<Pair<String, String>>
}

/**
 * The evidence that is about one request rather than about the key: a Play Integrity token, which is made for a nonce that hashes
 * the request's own DPoP proof (`NativeAttestation.integrityNonce`). It is read after the proof is minted, because the nonce needs
 * the proof's `jti`, and again for every proof, because a retry after a nonce challenge carries a new proof.
 *
 * Evidence, never a permission, like [NativeStartAttestation]: what the device cannot give is an empty list, and edge's policy for
 * the client decides whether a request without it is acceptable.
 */
@VersolaInternalApi
public fun interface NativeStartProofEvidence {
    public suspend fun fields(jti: String): List<Pair<String, String>>
}

/** The parts of the attestation contract that are bytes and names, fixed by the spec and shared with edge. */
@VersolaInternalApi
public object NativeAttestation {

    /** Domain separator of everything hashed for edge: a hash made for this purpose is good for no other. */
    private const val DOMAIN: String = "versola-attest-v1"

    /**
     * The Android Key Attestation challenge for a client: `SHA-256("versola-attest-v1\n" + clientId)`.
     * It names the client a chain was made for, so a chain made for one is not presented to another.
     * Not a secret, and not a freshness value: the chain is useless without the key it attests, which
     * is the key every request is signed with.
     */
    public fun androidChallenge(clientId: String): ByteArray =
        MessageDigest.getInstance("SHA-256").digest("$DOMAIN\n$clientId".toByteArray(Charsets.UTF_8))

    /**
     * The Play Integrity nonce of one request: `SHA-256("versola-attest-v1\n" + clientId + "\n" + jkt + "\n" + jti)` in URL-safe
     * base64 without padding or wrapping, which is what Play Integrity requires of a nonce. `jkt` is the thumbprint of the DPoP key
     * and `jti` the `jti` of the proof sent on the same request, so a verdict is good for one request by one key.
     */
    public fun integrityNonce(clientId: String, jkt: String, jti: String): String {
        val hash = MessageDigest.getInstance("SHA-256").digest("$DOMAIN\n$clientId\n$jkt\n$jti".toByteArray(Charsets.UTF_8))
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hash)
    }

    /**
     * The form fields for a Play Integrity token: the token alone, since `attestation_platform` is the one field of the evidence that
     * must not repeat and the key attestation's fields already carry it. Nothing when there is none.
     */
    public fun integrityFields(token: String?): List<Pair<String, String>> =
        if (token.isNullOrEmpty()) emptyList() else listOf("attestation_integrity_token" to token)

    /**
     * The `jti` of a DPoP proof, read from its payload without checking the signature: the proof is the SDK's own, minted a moment
     * ago, and only its identifier is wanted. Null for anything that is not a three-part JWS with a string `jti`.
     */
    public fun jtiOf(proof: String): String? {
        val parts = proof.split('.')
        if (parts.size != 3) return null
        return try {
            val payload = String(Base64.getUrlDecoder().decode(parts[1]), Charsets.UTF_8)
            Regex("\"jti\"\\s*:\\s*\"([^\"]+)\"").find(payload)?.groupValues?.get(1)
        } catch (e: IllegalArgumentException) {
            null
        }
    }

    /**
     * The form fields for an Android Key Attestation chain (leaf first, DER): the platform, and each
     * certificate in base64 under a field that repeats. Nothing for a key with no chain.
     */
    public fun androidFields(chain: List<ByteArray>?): List<Pair<String, String>> {
        if (chain.isNullOrEmpty()) return emptyList()
        val encoder = Base64.getEncoder()
        return listOf("attestation_platform" to "android") +
            chain.map { "attestation_chain" to encoder.encodeToString(it) }
    }
}
