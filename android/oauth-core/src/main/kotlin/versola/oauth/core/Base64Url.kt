package versola.oauth.core

import java.util.Base64

/**
 * base64url without padding — RFC 7636 §A for PKCE, RFC 7515 §2 everywhere else.
 *
 * `java.util.Base64` is API 26+, which is the SDK's floor (#1 §4), so `android.util.Base64`
 * and its Android-only flag constants are not needed. That also keeps this testable in a
 * plain JVM unit test.
 */
internal object Base64Url {

    private val encoder: Base64.Encoder = Base64.getUrlEncoder().withoutPadding()
    private val decoder: Base64.Decoder = Base64.getUrlDecoder()

    fun encode(bytes: ByteArray): String = encoder.encodeToString(bytes)

    fun decode(value: String): ByteArray = decoder.decode(value)
}
