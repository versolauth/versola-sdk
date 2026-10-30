package versola.sdk.storage

import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.security.KeyStore
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import versola.oauth.core.PendingAuthorizationRequest

/**
 * The Keystore-backed storage while an app holds every thread of `Dispatchers.IO`: 80 callers
 * parked in a blocking `execute()`, each waiting for a refresh that has to unwrap the refresh token
 * and write the rotated one. Real `HardwareKeyProvider`, the stores built with their default scope,
 * as the facade builds them. The JVM tier proves the stores' own scheduling against a fake key
 * provider (`StorageIoSaturationTest`); this is the half only a Keystore can show, that its
 * `wrap` and `unwrap` are not waiting on the dispatcher the app has exhausted either.
 *
 * Its own class because a regression is a hang, which would stall the whole instrumentation run;
 * [IoSaturation] puts a hard deadline on each case.
 */
@RunWith(AndroidJUnit4::class)
class StorageIoSaturationInstrumentedTest {

    private val alias = "versola.test.storage-key-saturated"
    private val context: Context = InstrumentationRegistry.getInstrumentation().targetContext
    private val files = mutableListOf<File>()

    @Before
    @After
    fun clean() {
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry(alias)
        files.forEach { it.delete() }
    }

    private fun file(name: String) = File(context.noBackupFilesDir, "versola-test-$name-${System.nanoTime()}").also { files += it }

    @Test
    fun theKeystoreKeyWrapsAndUnwrapsWhileIoIsSaturated() {
        val provider = HardwareKeyProvider(alias)
        val plaintext = "8xLOxBtZp8-refresh-token-value".toByteArray()

        val unwrapped = IoSaturation.start().use { io ->
            io.whileSaturated {
                // The first wrap generates the key: the slowest thing the Keystore does.
                provider.unwrap(provider.wrap(plaintext.copyOf()))
            }
        }

        assertArrayEquals(plaintext, unwrapped)
    }

    @Test
    fun theCredentialStoreRoundTripsThroughTheRealKeyWhileIoIsSaturated() {
        val store = DataStoreCredentialStore(file("credentials"), HardwareKeyProvider(alias))

        val seen = IoSaturation.start().use { io ->
            io.whileSaturated {
                store.save("the-refresh-token".toByteArray(), "the.id.token")
                val first = store.useRefreshToken { String(it) }
                store.replaceRefreshToken("rotated".toByteArray(), "the.id.token.2")
                val second = store.useRefreshToken { String(it) }
                store.clear()
                listOf(first, second, store.hasGrant())
            }
        }

        assertEquals(listOf("the-refresh-token", "rotated", false), seen)
    }

    @Test
    fun thePendingStoreRoundTripsThroughTheRealKeyWhileIoIsSaturated() {
        val store = FilePendingAuthorizationStore(file("pending"), HardwareKeyProvider(alias))
        val request = PendingAuthorizationRequest(
            state = "the-state",
            nonce = "the-nonce",
            codeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            scopes = listOf("openid"),
            redirectUri = "https://app.example.com/oauth",
            acrValues = emptyList(),
            maxAge = null,
            createdAtEpochMillis = 1_700_000_000_000,
        )

        val loaded = IoSaturation.start().use { io ->
            io.whileSaturated {
                store.save(request)
                val read = store.load()
                store.clear()
                read?.state to store.load()
            }
        }

        assertEquals("the-state", loaded.first)
        assertNull(loaded.second)
    }
}
