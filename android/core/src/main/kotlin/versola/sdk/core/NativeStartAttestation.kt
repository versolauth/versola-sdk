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
