package versola.sdk.conformance

import java.util.UUID
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import okhttp3.Credentials
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

/**
 * What a scenario needs registered before the SDK is configured, provisioned through
 * Central's management API the way `e2e/.../support/EdgeFixture.scala` does it — same
 * endpoints, same JSON, same ordering — so the SDK is tested against the registration a
 * real deployment makes rather than a shape this driver invented.
 *
 * Every entity is named uniquely per run: Central has no per-test isolation and most ids are
 * caller-chosen, so a leftover from a failed run must never collide with the next.
 */
class CentralClient(private val stack: Stack, private val http: OkHttpClient) {

    private val json = Json { ignoreUnknownKeys = true }
    private val authorization = Credentials.basic("central", stack.centralSecret)

    class Fixture(
        val tenantId: String,
        val clientId: String,
        val redirectUri: String,
        val login: String,
        val password: String,
        val resourceId: String,
        val resourceUri: String,
        val roleId: String,
        val permission: String,
    )

    /**
     * A `standard`-profile tenant served by the same edge as `default`, a public DPoP-bound
     * client with a login+password flow, a user with a password, a proxied resource with one
     * permitted `GET /items`, and the role that grants it. Scenarios 01–20's preconditions.
     */
    fun provisionStandardFixture(redirectUri: String, upstream: String): Fixture =
        provision(profile = "standard", native = false, redirectUri = redirectUri, upstream = upstream)

    /**
     * Scenario 21's preconditions: a `fapi2` tenant and an edge-fronted native client —
     * `applicationType: native`, `tls_client_auth` by a certificate central issues from its
     * own CA for the edge fronting it (#440), PAR required, DPoP-bound tokens, one https App
     * Link — the registration `NativeAppFlowSpec` makes.
     */
    fun provisionNativeFixture(redirectUri: String, upstream: String): Fixture =
        provision(profile = "fapi2", native = true, redirectUri = redirectUri, upstream = upstream)

    private fun provision(profile: String, native: Boolean, redirectUri: String, upstream: String): Fixture {
        val suffix = UUID.randomUUID().toString().replace("-", "").take(10)
        val tenantId = "sdk-$suffix"
        val clientId = "sdk-client-$suffix"
        val roleId = "sdk-role-$suffix"
        val permission = "sdk_api:s$suffix"
        val login = "sdk-user-$suffix"
        val password = "Sdk-${suffix.takeLast(8)}-1!"
        val resourceId = "sdk-resource-$suffix"
        val endpointId = UUID.randomUUID().toString()

        val tenants = get("/configuration/tenants").obj()["tenants"]!!.jsonArray
        val edgeId = tenants.map { it.jsonObject }
            .firstOrNull { it["id"]?.jsonPrimitive?.content == "default" }
            ?.get("edgeId")?.jsonPrimitive?.content

        expect("create the tenant") {
            post(
                "/configuration/tenants",
                buildJsonObject {
                    put("id", tenantId)
                    put("description", "SDK conformance tenant")
                    putJsonObject("submissionLimits") {
                        putJsonArray("otpRequest") { add(rateLimit(2, 60)) }
                        putJsonArray("otpSubmit") { add(rateLimit(3, 120)) }
                        putJsonArray("passwordSubmit") { add(rateLimit(5, 900)) }
                        putJsonArray("passkeyAssertion") { add(rateLimit(5, 300)) }
                        put("banDurationSeconds", 1800)
                    }
                    edgeId?.let { put("edgeId", it) }
                    put("securityProfile", profile)
                },
            )
        }

        expect("register the client") {
            post(
                "/configuration/clients",
                buildJsonObject {
                    put("tenantId", tenantId)
                    put("id", clientId)
                    putJsonObject("clientName") { put("en", "SDK conformance client") }
                    putJsonArray("redirectUris") { add(redirectUri) }
                    putJsonArray("allowedScopes") { add("openid"); add("profile"); add("offline_access") }
                    putJsonArray("audience") {}
                    putJsonArray("permissions") {}
                    put("accessTokenTtl", 3600)
                    put("theme", "default")
                    putJsonObject("authFlow") {
                        putJsonObject("primary") {
                            putJsonArray("credentials") { add("login") }
                            put("inlinePassword", true)
                            putJsonArray("factors") {}
                        }
                        put("passkey", null as String?)
                        putJsonObject("equivalents") {}
                        put("otpType", "sms")
                    }
                    put("otpTemplateId", "default")
                    put("frontChannelLogoutSessionRequired", false)
                    // Direct: a public client, the SDK's own position and what a `standard`
                    // tenant admits. Through edge: what a `fapi2` tenant demands, with edge
                    // authenticating by a certificate central issues for it. DPoP-bound
                    // tokens either way — what the SDK ships by default.
                    put("authMethod", if (native) "tls_client_auth" else "none")
                    put("certificateBoundAccessTokens", false)
                    put("dpopBoundAccessTokens", true)
                    put("requireSignedRequestObject", false)
                    put("requirePushedAuthorizationRequests", native)
                    putJsonArray("dpopSigningAlgs") {}
                    if (native) put("applicationType", "native")
                    put("issueEdgeClientCertificate", native)
                    put("enrollEdgeClientCertificate", false)
                },
            )
        }

        val userId = post("/users", buildJsonObject { put("login", login) })
            .also { expect("register the user") { it } }
            .obj()["id"]!!.jsonPrimitive.content
        expect("flush the user outbox") { postEmpty("/service/users/outbox/flush") }
        expect("set the password") {
            post("/users/password/set", buildJsonObject { put("userId", userId); put("password", password) })
        }

        expect("register the proxied resource") {
            post(
                "/configuration/resources",
                buildJsonObject {
                    put("tenantId", tenantId)
                    put("resourceId", resourceId)
                    put("resource", upstream)
                    putJsonArray("audience") { add(clientId) }
                    putJsonArray("endpoints") {
                        add(
                            buildJsonObject {
                                put("id", endpointId)
                                put("method", "GET")
                                put("path", "/items")
                                put("fetchUserInfo", false)
                                putJsonArray("inject") {}
                            },
                        )
                    }
                    put("internal", false)
                },
            )
        }
        expect("register the permission") {
            post(
                "/configuration/permissions",
                buildJsonObject {
                    put("tenantId", tenantId)
                    put("permission", permission)
                    putJsonObject("description") { put("en", "SDK conformance") }
                    putJsonArray("endpointIds") { add(endpointId) }
                },
            )
        }
        expect("register the role") {
            post(
                "/configuration/roles",
                buildJsonObject {
                    put("tenantId", tenantId)
                    put("id", roleId)
                    putJsonObject("description") { put("en", "SDK conformance") }
                    putJsonArray("permissions") { add(permission) }
                },
            )
        }
        expect("assign the role") {
            patch(
                "/users/roles",
                buildJsonObject {
                    put("userId", userId)
                    put("tenantId", tenantId)
                    putJsonArray("add") { add(roleId) }
                    putJsonArray("remove") {}
                },
            )
        }
        expect("flush the user outbox") { postEmpty("/service/users/outbox/flush") }
        syncConfiguration()

        return Fixture(tenantId, clientId, redirectUri, login, password, resourceId, upstream, roleId, permission)
    }

    /** Makes auth and edge reload their caches now rather than on the next refresh interval. */
    fun syncConfiguration() {
        expect("sync auth's configuration") { postEmpty("/service/configuration/sync") }
        val edgeSync = Request.Builder()
            .url("${stack.edgeUrl}/service/configuration/sync")
            .header("Authorization", Credentials.basic("edge", stack.edgeInternalSecret))
            .post(ByteArray(0).toRequestBody(null))
            .build()
        // Retried on a 5xx the way the reference client does: a pooled connection central
        // closed while idle surfaces as a 500 on the first attempt.
        repeat(10) {
            http.newCall(edgeSync).execute().use { if (it.code < 500) return }
            Thread.sleep(500)
        }
        error("edge's configuration sync kept failing")
    }

    class Reply(val status: Int, val body: String) {
        fun obj(): JsonObject = Json.parseToJsonElement(body).jsonObject
    }

    private fun get(path: String): Reply = send(Request.Builder().url("${stack.centralUrl}$path").get())
    private fun postEmpty(path: String): Reply =
        send(Request.Builder().url("${stack.centralUrl}$path").post(ByteArray(0).toRequestBody(null)))
    private fun post(path: String, body: JsonObject): Reply =
        send(Request.Builder().url("${stack.centralUrl}$path").post(body.toString().toRequestBody(JSON)))
    private fun patch(path: String, body: JsonObject): Reply =
        send(Request.Builder().url("${stack.centralUrl}$path").patch(body.toString().toRequestBody(JSON)))

    private fun send(builder: Request.Builder): Reply =
        http.newCall(builder.header("Authorization", authorization).build()).execute().use {
            Reply(it.code, it.body.string())
        }

    private inline fun expect(what: String, call: () -> Reply) {
        val reply = call()
        check(reply.status in 200..299) { "could not $what: HTTP ${reply.status} ${reply.body}" }
    }

    private fun rateLimit(maxAttempts: Int, windowSeconds: Int) = buildJsonObject {
        put("maxAttempts", maxAttempts)
        put("windowSeconds", windowSeconds)
    }

    private companion object {
        val JSON = "application/json".toMediaType()
    }
}
