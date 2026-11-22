package versola.sdk

import java.io.BufferedInputStream
import java.io.InputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.URLDecoder
import java.util.Base64
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.awaitCancellation
import versola.oauth.core.BrowserAuthorizationSession
import versola.oauth.core.BrowserOutcome
import versola.oauth.core.CredentialKeyProvider

// Test support for :sdk, which has no MockWebServer on its test classpath (and gets none here:
// a dependency is not this change's to add). A plain socket server is enough for what is asserted:
// the method, target, headers and form body of each request, and a scripted answer.

internal const val REDIRECT_URI = "https://app.example.com/oauth"
internal const val POST_LOGOUT_REDIRECT_URI = "https://app.example.com/signed-out"

/** A JVM stand-in for the Keystore-wrapped storage key: reversible, never secure, never shipped. */
internal object ReversingKeyProvider : CredentialKeyProvider {
    override suspend fun wrap(plaintext: ByteArray): ByteArray = plaintext.reversedArray()
    override suspend fun unwrap(blob: ByteArray): ByteArray = blob.reversedArray()
}

/** One request as the server received it. Header names are lower-cased. */
internal class HttpCall(
    val method: String,
    val target: String,
    val headers: Map<String, List<String>>,
    val body: String,
) {
    val path: String get() = target.substringBefore('?')
    fun header(name: String): String? = headers[name.lowercase()]?.firstOrNull()
    fun headerCount(name: String): Int = headers[name.lowercase()]?.size ?: 0

    /** `application/x-www-form-urlencoded` fields, decoded; a repeated one keeps every value. */
    val form: Map<String, List<String>>
        get() = body.split('&').filter { it.contains('=') }
            .map { decode(it.substringBefore('=')) to decode(it.substringAfter('=')) }
            .groupBy({ it.first }, { it.second })

    fun field(name: String): String? = form[name]?.singleOrNull()

    /** The claims of the DPoP proof this request carried. */
    val proofClaims: Map<String, String>? get() = header("DPoP")?.let { jwtClaims(it) }
}

internal class HttpReply(
    val status: Int = 200,
    val headers: Map<String, String> = emptyMap(),
    val body: String = "",
)

internal fun decode(value: String): String = URLDecoder.decode(value, "UTF-8")

internal fun queryOf(uri: String): Map<String, String> =
    uri.substringAfter('?', "").split('&').filter { it.contains('=') }
        .associate { decode(it.substringBefore('=')) to decode(it.substringAfter('=')) }

/**
 * The payload of a JWT as flat text. The claims the tests read are strings and integers, which is
 * all this reads (no JSON library is on this module's test classpath, and none is added for it).
 */
internal fun jwtClaims(jwt: String): Map<String, String> {
    val payload = String(Base64.getUrlDecoder().decode(jwt.split('.')[1]), Charsets.UTF_8)
    return Regex(""""([^"]+)"\s*:\s*(?:"((?:[^"\\]|\\.)*)"|(-?\d+))""").findAll(payload)
        .associate { it.groupValues[1] to it.groupValues[2].ifEmpty { it.groupValues[3] } }
}

/** HTTP/1.1 over a loopback socket, one request per connection, every request recorded. */
internal class FakeServer(private val handler: (HttpCall) -> HttpReply) : AutoCloseable {
    private val socket = ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))
    val url: String = "http://127.0.0.1:${socket.localPort}"
    val requests = CopyOnWriteArrayList<HttpCall>()
    private val arrivals = LinkedBlockingQueue<HttpCall>()

    init {
        Thread({
            while (!socket.isClosed) {
                val client = try {
                    socket.accept()
                } catch (e: java.io.IOException) {
                    return@Thread
                }
                Thread({ serve(client) }, "fake-edge-connection").apply { isDaemon = true }.start()
            }
        }, "fake-edge-accept").apply { isDaemon = true }.start()
    }

    /**
     * The next request matching [predicate] that arrives within [timeoutMillis], or null. A bound
     * on awaiting an effect that is detached from the call under test, never a delay: it returns
     * the moment the request is there.
     */
    fun await(timeoutMillis: Long = 5_000, predicate: (HttpCall) -> Boolean): HttpCall? {
        val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis)
        while (true) {
            val remaining = deadline - System.nanoTime()
            if (remaining <= 0) return null
            val call = arrivals.poll(remaining, TimeUnit.NANOSECONDS) ?: return null
            if (predicate(call)) return call
        }
    }

    /** Forgets what was awaited so far, so [await] sees only what arrives from now on. */
    fun drain() {
        arrivals.clear()
    }

    private fun serve(client: Socket) {
        client.use { s ->
            s.soTimeout = 15_000
            val input = BufferedInputStream(s.getInputStream())
            val requestLine = readLine(input) ?: return
            val (method, target) = requestLine.split(' ')
            val headers = mutableMapOf<String, MutableList<String>>()
            while (true) {
                val line = readLine(input) ?: return
                if (line.isEmpty()) break
                headers.getOrPut(line.substringBefore(':').trim().lowercase()) { mutableListOf() }.add(line.substringAfter(':').trim())
            }
            val length = headers["content-length"]?.firstOrNull()?.toInt() ?: 0
            val body = ByteArray(length)
            var read = 0
            while (read < length) {
                val n = input.read(body, read, length - read)
                if (n < 0) return
                read += n
            }
            val call = HttpCall(method, target, headers, String(body, Charsets.UTF_8))
            requests += call
            arrivals.put(call)
            val reply = handler(call)
            val payload = reply.body.toByteArray(Charsets.UTF_8)
            val head = buildString {
                append("HTTP/1.1 ${reply.status} X\r\n")
                reply.headers.forEach { (k, v) -> append("$k: $v\r\n") }
                append("Content-Length: ${payload.size}\r\nConnection: close\r\n\r\n")
            }
            s.getOutputStream().apply {
                write(head.toByteArray(Charsets.UTF_8))
                write(payload)
                flush()
            }
        }
    }

    private fun readLine(input: InputStream): String? {
        val line = StringBuilder()
        while (true) {
            val b = input.read()
            if (b < 0) return if (line.isEmpty()) null else line.toString()
            if (b == '\n'.code) return line.toString().trimEnd('\r')
            line.append(b.toChar())
        }
    }

    override fun close() {
        socket.close()
    }
}

/** What `/native/start` answered for one login, and what the SDK sent to get it. */
internal class StartRecord(
    val state: String,
    val nonce: String,
    val requestUri: String,
    val blob: String,
    val scope: String,
)

internal class Issued(val accessToken: String, val refreshToken: String, val idToken: String)

/**
 * Edge, scripted: `/native/start`, `/native/complete`, `/native/token`, `/native/revoke` and a
 * resource. It plays the server of `spec/versola-sdk-api.md` sections 5 and 7 as far as a JVM test
 * can: it holds no keys and verifies no proof, so what it can say about the proofs is what the
 * request carried (the `DPoP` header and its claims), not that auth would accept it.
 *
 * Its ID token is three segments with a dummy signature, which is what the SDK is entitled to
 * judge (`spec/versola-sdk-api.md` section 9: the signature is not verified).
 */
internal class FakeEdge(val clientId: String) : AutoCloseable {
    val server = FakeServer { handle(it) }
    val url: String get() = server.url
    val requests: List<HttpCall> get() = server.requests

    /** What the ID token's `iss` is: the configured issuer unless a test says otherwise. */
    var tokenIssuer: String? = null
    var subject: String = "alice"

    /** Members of the ID token a test overrides; a null value removes the member. */
    var claimOverrides: Map<String, Any?> = emptyMap()

    /** Members of the start answer a test overrides; a null value removes the member. */
    var startOverrides: Map<String, Any?> = emptyMap()

    val starts = CopyOnWriteArrayList<StartRecord>()
    val issued = CopyOnWriteArrayList<Issued>()

    val authorizationEndpoint: String get() = "$url/authorize"

    /** Auth's mutual-TLS addresses as `/native/start` names them: signed for, never dialled. */
    val tokenEndpoint: String get() = "$url/auth-mtls/token"
    val revocationEndpoint: String get() = "$url/auth-mtls/revoke"

    fun requestsTo(prefix: String): List<HttpCall> = requests.filter { it.path.startsWith(prefix) }

    private fun handle(call: HttpCall): HttpReply = when {
        call.method == "POST" && call.path == "/native/start/$clientId" -> start(call)
        call.method == "POST" && call.path == "/native/complete/$clientId" -> complete(call)
        call.method == "POST" && call.path == "/native/token/$clientId" -> refresh()
        call.method == "POST" && call.path == "/native/revoke/$clientId" -> HttpReply(200)
        call.path.startsWith("/resources/") -> HttpReply(200, mapOf("Content-Type" to "text/plain"), "ok")
        else -> HttpReply(404)
    }

    private fun start(call: HttpCall): HttpReply {
        val n = starts.size + 1
        val record = StartRecord(
            state = "state-$n",
            nonce = call.field("nonce").orEmpty(),
            requestUri = "v1.cell-a.request-$n",
            blob = "blob-$n",
            scope = call.field("scope").orEmpty(),
        )
        starts += record
        val answer: Map<String, Any?> = mapOf(
            "client_id" to clientId,
            "request_uri" to record.requestUri,
            "expires_in" to 60,
            "authorization_endpoint" to authorizationEndpoint,
            "state" to record.state,
            "blob" to record.blob,
            "token_endpoint" to tokenEndpoint,
            "revocation_endpoint" to revocationEndpoint,
        ) + startOverrides
        return HttpReply(200, mapOf("Content-Type" to "application/json"), json(answer))
    }

    private fun complete(call: HttpCall): HttpReply {
        val record = starts.firstOrNull { it.state == call.field("state") }
            ?: return HttpReply(400, mapOf("Content-Type" to "application/json"), """{"error":"invalid_grant"}""")
        val n = issued.size + 1
        val idToken = jwt(
            mapOf(
                "iss" to (tokenIssuer ?: url),
                "sub" to subject,
                "aud" to clientId,
                "exp" to now() + 3600,
                "iat" to now(),
                "auth_time" to now(),
                "nonce" to record.nonce,
            ) + claimOverrides,
        )
        val tokens = Issued("at-$n", "rt-$n", idToken)
        issued += tokens
        return HttpReply(
            200,
            mapOf("Content-Type" to "application/json"),
            json(
                mapOf(
                    "access_token" to tokens.accessToken,
                    "token_type" to "DPoP",
                    "expires_in" to 3600,
                    "refresh_token" to tokens.refreshToken,
                    "id_token" to tokens.idToken,
                    "scope" to record.scope,
                ),
            ),
        )
    }

    private fun refresh(): HttpReply {
        val last = issued.last()
        return HttpReply(
            200,
            mapOf("Content-Type" to "application/json"),
            json(
                mapOf(
                    "access_token" to "at-renewed-${requestsTo("/native/token").size}",
                    "token_type" to "DPoP",
                    "expires_in" to 3600,
                    "refresh_token" to last.refreshToken,
                ),
            ),
        )
    }

    override fun close() {
        server.close()
    }

    companion object {
        fun now(): Long = System.currentTimeMillis() / 1000

        /** Three segments and a signature nobody can verify: the SDK is not asked to. */
        fun jwt(claims: Map<String, Any?>): String {
            val encoder = Base64.getUrlEncoder().withoutPadding()
            val header = encoder.encodeToString("""{"alg":"ES256","typ":"JWT"}""".toByteArray())
            val payload = encoder.encodeToString(json(claims).toByteArray())
            return "$header.$payload.${encoder.encodeToString("not-a-signature".toByteArray())}"
        }

        fun json(members: Map<String, Any?>): String = members.entries.filter { it.value != null }.joinToString(",", "{", "}") { (k, v) ->
            "\"$k\":" + when (v) {
                is Number -> v.toString()
                is List<*> -> v.joinToString(",", "[", "]") { "\"$it\"" }
                else -> "\"$v\""
            }
        }
    }
}

/**
 * The system browser, scripted: it answers the authorization request with the redirect the
 * start's `state` and the code call for, and the end-session request with the post-logout
 * redirect that carries the `state` it was given.
 */
internal class ScriptedBrowser(private val edge: FakeEdge) : BrowserAuthorizationSession {
    val opened = CopyOnWriteArrayList<String>()

    /** The `iss` on the redirect; null leaves it off. */
    var iss: String? = edge.url

    /** When set, the browser stays open until it completes, as a user who has not signed in yet. */
    var gate: CompletableDeferred<Unit>? = null

    /** Never answers, as a tab the user left open. */
    var hold: Boolean = false

    override suspend fun authorize(uri: String): BrowserOutcome {
        opened += uri
        gate?.await()
        if (hold) awaitCancellation()
        val query = queryOf(uri)
        if (uri.substringBefore('?').endsWith("/logout")) {
            return BrowserOutcome.Redirect("$POST_LOGOUT_REDIRECT_URI?state=${java.net.URLEncoder.encode(query.getValue("state"), "UTF-8")}")
        }
        val start = edge.starts.last { it.requestUri == query["request_uri"] }
        return BrowserOutcome.Redirect(
            buildString {
                append("$REDIRECT_URI?code=the-code&state=${start.state}")
                iss?.let { append("&iss=${java.net.URLEncoder.encode(it, "UTF-8")}") }
            },
        )
    }

    override suspend fun awaitPendingRedirect(): BrowserOutcome = awaitCancellation()
}
