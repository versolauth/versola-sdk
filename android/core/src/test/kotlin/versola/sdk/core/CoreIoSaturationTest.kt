package versola.sdk.core

import java.io.File
import kotlinx.coroutines.runBlocking
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import okhttp3.OkHttpClient
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import versola.oauth.core.DiscoveryClient
import versola.oauth.core.DiscoveryService
import versola.oauth.core.DpopProofSource
import versola.oauth.core.FileProviderMetadataCache
import versola.oauth.core.ProviderMetadata
import versola.oauth.core.TokenBinding
import versola.oauth.core.VersolaConfiguration

private class QuietProofSource : DpopProofSource {
    override suspend fun proof(method: String, url: String, accessToken: String?): String = "proof"
    override fun observe(url: String, dateHeader: String?, nonceHeader: String?) = Unit
}

/**
 * The edge back channel while an app holds every thread of `Dispatchers.IO`, as
 * `oauth-core`'s `SdkIoSaturationTest` does for the generic path. Its own file because a
 * regression is a hang; [IoSaturation] (a copy of the `:oauth-core` helper, which is internal to
 * that module's tests) bounds each case with a hard deadline.
 */
class CoreIoSaturationTest {

    @get:Rule
    val folder: TemporaryFolder = TemporaryFolder()

    private lateinit var server: MockWebServer
    private lateinit var edge: String

    @Before
    fun start() {
        server = MockWebServer()
        server.start()
        edge = server.url("/").toString().trimEnd('/')
    }

    @After
    fun stop() {
        server.close()
    }

    // AUDIT: C3 - EdgeNativeTokenClient.resolveEndpoints() reads FileNativeEndpointsStore on Dispatchers.IO.
    @Test
    fun `AUDIT C3 an edge refresh finishes while every thread of IO is held`() {
        val endpointsFile = File(folder.newFolder(), "endpoints.json")
        val store = FileNativeEndpointsStore(endpointsFile)
        runBlocking { store.save(NativeEndpoints("https://id.example.com:9008/token", "https://id.example.com:9008/revoke")) }
        server.enqueue(
            MockResponse.Builder()
                .code(200)
                .setHeader("Content-Type", "application/json")
                .body("""{"access_token":"at","token_type":"DPoP","expires_in":3600,"refresh_token":"rt2"}""")
                .build(),
        )
        val metadata = ProviderMetadata(
            issuer = "https://id.example.com",
            authorizationEndpoint = "https://id.example.com/authorize",
            tokenEndpoint = "https://id.example.com/token",
            dpopSigningAlgValuesSupported = listOf("ES256"),
        )
        val client = EdgeNativeTokenClient(
            configuration = VersolaConfiguration.create("https://id.example.com", "mobile-app", "https://app.example.com/oauth"),
            edgeBaseUrl = edge,
            httpClient = OkHttpClient(),
            dpop = QuietProofSource(),
            discovery = DiscoveryService(
                issuer = "https://id.example.com",
                client = object : DiscoveryClient {
                    override suspend fun fetch(issuer: String): ProviderMetadata = metadata
                },
                cache = FileProviderMetadataCache(File(folder.newFolder(), "metadata.json")),
            ),
            endpoints = store,
            tokenBinding = TokenBinding.Dpop(),
        )

        val refreshed = IoSaturation.start().use { io ->
            io.whileSaturated { client.refresh("rt1".toByteArray(), "idem-key") }
        }

        assertEquals("at", refreshed.accessToken)
    }

    // AUDIT: C3 - the endpoints file itself is read and written on Dispatchers.IO.
    @Test
    fun `AUDIT C3 the native endpoints file is written and read while every thread of IO is held`() {
        val store = FileNativeEndpointsStore(File(folder.newFolder(), "endpoints.json"))
        val endpoints = NativeEndpoints("https://id.example.com:9008/token", "https://id.example.com:9008/revoke")

        val loaded = IoSaturation.start().use { io ->
            io.whileSaturated {
                store.save(endpoints)
                store.load()
            }
        }

        assertEquals(endpoints, loaded)
    }
}
