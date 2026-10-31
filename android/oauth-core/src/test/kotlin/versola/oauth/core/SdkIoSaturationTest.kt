package versola.oauth.core

import java.io.File
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import okhttp3.OkHttpClient
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * The SDK's own blocking work (the token request, discovery, the key set, userinfo, pushed
 * authorization, and the files the caches keep) while an app holds every thread of
 * `Dispatchers.IO`: 80 callers parked in `execute()`, say, each waiting for a refresh that needs
 * one of those threads for its token request. Each case is one site; each must finish.
 *
 * Its own file because a regression here is a hang, and a hung test would take every other test of
 * the module's JVM with it; [IoSaturation] bounds each case with a hard deadline instead.
 */
class SdkIoSaturationTest {

    @get:Rule
    val folder: TemporaryFolder = TemporaryFolder()

    private lateinit var server: MockWebServer
    private lateinit var issuer: String

    @Before
    fun start() {
        server = MockWebServer()
        server.start()
        issuer = server.url("/").toString().trimEnd('/')
    }

    @After
    fun stop() {
        server.close()
    }

    private fun metadata() = ProviderMetadata(
        issuer = issuer,
        authorizationEndpoint = "$issuer/authorize",
        tokenEndpoint = "$issuer/token",
        revocationEndpoint = "$issuer/revoke",
        pushedAuthorizationRequestEndpoint = "$issuer/par",
    )

    private fun json(body: String) = MockResponse.Builder()
        .code(200)
        .setHeader("Content-Type", "application/json")
        .body(body)
        .build()

    @Test
    fun `discovery is fetched`() {
        server.enqueue(json(discoveryJson.encodeToString(ProviderMetadata.serializer(), metadata())))

        val fetched = IoSaturation.start().use { io ->
            io.whileSaturated { HttpDiscoveryClient(OkHttpClient()).fetch(issuer) }
        }

        assertEquals(issuer, fetched.issuer)
    }

    @Test
    fun `the discovery cache is written, read and cleared`() {
        val cache = FileProviderMetadataCache(File(folder.newFolder(), "metadata.json"))

        val loaded = IoSaturation.start().use { io ->
            io.whileSaturated {
                cache.save(metadata())
                val expiry = cache.expiresAtEpochMillis()
                val read = cache.load()
                cache.clear()
                Triple(expiry, read, cache.load())
            }
        }

        assertNotNull(loaded.first)
        assertEquals(issuer, loaded.second?.issuer)
        assertNull(loaded.third)
    }

    @Test
    fun `the key set cache is written, read and cleared`() {
        val cache = FileJwksCache(File(folder.newFolder(), "jwks.json"))

        val loaded = IoSaturation.start().use { io ->
            io.whileSaturated {
                cache.save("""{"keys":[]}""", 60_000)
                val read = cache.load(0)
                cache.clear()
                read to cache.load(0)
            }
        }

        assertEquals("""{"keys":[]}""", loaded.first)
        assertNull(loaded.second)
    }

    @Test
    fun `the key set is fetched`() {
        val document = Jose.jwks(Jose.jwk(Jose.p256, "p256"))
        server.enqueue(MockResponse.Builder().code(200).body(document).build())

        val loaded = IoSaturation.start().use { io ->
            io.whileSaturated { JwksClient(OkHttpClient()).keys("$issuer/jwks.json", forceRefresh = true) }
        }

        assertEquals(listOf("p256"), loaded.keys.keys.map { it.keyId })
    }

    @Test
    fun `a refresh and a revocation reach the token endpoint`() {
        server.enqueue(
            json("""{"access_token":"at","token_type":"Bearer","expires_in":3600,"refresh_token":"rotated"}"""),
        )
        server.enqueue(MockResponse.Builder().code(200).build())
        val client = HttpTokenClient(
            configuration = VersolaConfiguration.create(
                issuer = "https://id.example.com",
                clientId = "mobile-app",
                redirectUri = "https://app.example.com/oauth",
            ),
            discovery = DiscoveryService(
                issuer = issuer,
                client = object : DiscoveryClient {
                    override suspend fun fetch(issuer: String): ProviderMetadata = metadata()
                },
                cache = FileProviderMetadataCache(File(folder.newFolder(), "metadata.json")),
            ),
            httpClient = OkHttpClient(),
            dpop = null,
            tokenBinding = TokenBinding.Bearer,
        )

        val issued = IoSaturation.start().use { io ->
            io.whileSaturated {
                val refreshed = client.refresh("the-refresh-token".toByteArray(), "idempotency-1")
                client.revoke("the-refresh-token".toByteArray())
                refreshed
            }
        }

        assertEquals("at", issued.accessToken)
        assertEquals(2, server.requestCount)
    }

    @Test
    fun `userinfo is fetched`() {
        server.enqueue(json("""{"sub":"user-1","name":"Alice Example"}"""))
        val client = HttpUserInfoClient(
            userinfoEndpoint = { "$issuer/userinfo" },
            httpClient = OkHttpClient(),
            dpop = null,
            verifier = JwsVerifier({ "$issuer/jwks.json" }, { emptyList() }, JwksClient(OkHttpClient())),
        )
        val tokens = object : AccessTokenSource {
            override suspend fun accessToken() = AccessToken("token-1", isDpopBound = false)
            override suspend fun renewAccessToken() = AccessToken("token-2", isDpopBound = false)
        }

        val info = IoSaturation.start().use { io -> io.whileSaturated { client.fetch(tokens, "user-1") } }

        assertEquals("user-1", info.subject)
    }

    @Test
    fun `an authorization request is pushed`() {
        server.enqueue(
            MockResponse.Builder()
                .code(201)
                .setHeader("Content-Type", "application/json")
                .body("""{"request_uri":"urn:ietf:params:oauth:request_uri:abc","expires_in":60}""")
                .build(),
        )
        val configuration = VersolaConfiguration.create(
            issuer = "https://id.example.com",
            clientId = "mobile-app",
            redirectUri = "https://app.example.com/oauth",
        )
        val starter = PushedAuthorizationStarter(configuration, OkHttpClient(), PushedAuthorization.WhenAdvertised)
        val request = AuthorizationRequest.create(configuration, scopes = setOf("openid"))

        IoSaturation.start().use { io ->
            io.whileSaturated { starter.start(request, metadata(), nowEpochMillis = 0) }
        }

        assertEquals(1, server.requestCount)
    }
}
