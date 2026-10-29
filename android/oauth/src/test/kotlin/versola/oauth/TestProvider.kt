package versola.oauth

import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.RSAPublicKey
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import java.util.Base64
import versola.oauth.core.BrowserAuthorizationSession
import versola.oauth.core.BrowserOutcome
import versola.oauth.core.CredentialKeyProvider

internal const val CLIENT_ID = "mobile"
internal const val REDIRECT_URI = "https://app.example.com/oauth"

/** A provider on a MockWebServer: discovery, JWKS and a signer for its ID tokens. */
internal class TestProvider(val server: MockWebServer) {
    val issuer: String = server.url("/").toString().trimEnd('/')
    val keys: KeyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()

    fun discovery(endSession: Boolean = true, revocation: Boolean = true, par: Boolean = false): String = buildString {
        append("""{"issuer":"$issuer","authorization_endpoint":"$issuer/authorize","token_endpoint":"$issuer/token",""")
        append(""""jwks_uri":"$issuer/jwks","userinfo_endpoint":"$issuer/userinfo",""")
        if (revocation) append(""""revocation_endpoint":"$issuer/revoke",""")
        if (endSession) append(""""end_session_endpoint":"$issuer/logout",""")
        if (par) append(""""pushed_authorization_request_endpoint":"$issuer/par",""")
        append(""""code_challenge_methods_supported":["S256"],"id_token_signing_alg_values_supported":["RS256"],""")
        append(""""scopes_supported":["openid","profile","offline_access"],"response_types_supported":["code"]}""")
    }

    fun jwks(): String {
        val public = keys.public as RSAPublicKey
        return """{"keys":[{"kty":"RSA","kid":"k1","alg":"RS256","use":"sig","n":"${unsigned(public.modulus)}","e":"${unsigned(public.publicExponent)}"}]}"""
    }

    fun idToken(nonce: String, subject: String = "alice", audience: String = CLIENT_ID, now: Long = System.currentTimeMillis() / 1000): String {
        val header = Base64.getUrlEncoder().withoutPadding().encodeToString("""{"alg":"RS256","kid":"k1","typ":"JWT"}""".toByteArray())
        val payload = Base64.getUrlEncoder().withoutPadding().encodeToString(
            """{"iss":"$issuer","sub":"$subject","aud":"$audience","exp":${now + 3600},"iat":$now,"nonce":"$nonce","auth_time":$now}""".toByteArray(),
        )
        val signature = Signature.getInstance("SHA256withRSA").apply {
            initSign(keys.private)
            update("$header.$payload".toByteArray())
        }.sign()
        return "$header.$payload.${Base64.getUrlEncoder().withoutPadding().encodeToString(signature)}"
    }

    fun json(body: String, code: Int = 200): MockResponse = MockResponse.Builder()
        .code(code)
        .setHeader("Content-Type", "application/json")
        .body(body)
        .build()

    private fun unsigned(value: BigInteger): String {
        val bytes = value.toByteArray()
        return Base64.getUrlEncoder().withoutPadding().encodeToString(if (bytes[0] == 0.toByte()) bytes.copyOfRange(1, bytes.size) else bytes)
    }
}

/** Answers the authorization request with a redirect for the state it carried, as a user would. */
internal class FakeBrowser(
    private val issuer: String,
    private val code: String = "the-code",
    private val withIss: Boolean = true,
) : BrowserAuthorizationSession {
    val launched = mutableListOf<String>()
    var nonceSeen: String? = null

    override suspend fun authorize(uri: String): BrowserOutcome {
        launched += uri
        val query = uri.substringAfter('?').split('&').associate { it.substringBefore('=') to java.net.URLDecoder.decode(it.substringAfter('='), "UTF-8") }
        nonceSeen = query["nonce"]
        val state = query.getValue("state")
        val redirect = buildString {
            append("$REDIRECT_URI?code=$code&state=$state")
            if (withIss) append("&iss=${java.net.URLEncoder.encode(issuer, "UTF-8")}")
        }
        return BrowserOutcome.Redirect(redirect)
    }

    override suspend fun awaitPendingRedirect(): BrowserOutcome = kotlinx.coroutines.awaitCancellation()
}

/** A JVM stand-in for the Keystore-wrapped key: reversible, never secure, never shipped. */
internal object ReversingKeyProvider : CredentialKeyProvider {
    override suspend fun wrap(plaintext: ByteArray): ByteArray = plaintext.reversedArray()
    override suspend fun unwrap(blob: ByteArray): ByteArray = blob.reversedArray()
}
