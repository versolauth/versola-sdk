package versola.sdk

import android.content.Context
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.suspendCancellableCoroutine
import versola.sdk.core.NativeAttestation
import versola.sdk.core.NativeStartProofEvidence

/**
 * The Play Integrity token an edge may ask for on `/native/start` (#423), for a build whose policy requires the Play Store's word
 * that it is the genuine, Play-recognised app on a device that meets Android's integrity bar.
 *
 * The nonce is a hash of the request (client, DPoP key, the `jti` of the proof sent with it), so the verdict is good for one request
 * by one key and a token captured from one login cannot start another. Google rate-limits token requests per app, and edge only
 * looks at the token when the client's policy asks for it, so this is made only when the integrator gave a Google Cloud project
 * number (`Versola.configure`), and each call to `/native/start` makes one.
 *
 * What the device cannot give is no token and no error: the caller reads a failure as no evidence, and edge's policy for the
 * client decides whether a request without it is acceptable.
 */
internal class PlayIntegrityEvidence(
    private val context: Context,
    private val cloudProjectNumber: Long,
    private val clientId: String,
    private val jkt: suspend () -> String,
) : NativeStartProofEvidence {

    override suspend fun fields(jti: String): List<Pair<String, String>> {
        val nonce = NativeAttestation.integrityNonce(clientId, jkt(), jti)
        val request = IntegrityTokenRequest.builder()
            .setNonce(nonce)
            .setCloudProjectNumber(cloudProjectNumber)
            .build()
        val token = suspendCancellableCoroutine { continuation ->
            IntegrityManagerFactory.create(context).requestIntegrityToken(request)
                .addOnSuccessListener { response -> continuation.resume(response.token()) }
                .addOnFailureListener { error -> continuation.resumeWithException(error) }
        }
        return NativeAttestation.integrityFields(token)
    }
}
