package versola.sdk.storage

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import versola.oauth.core.PendingAuthorizationRequest

/**
 * The stores while an app holds every thread of `Dispatchers.IO`: 80 callers parked in a blocking
 * `execute()`, each waiting for a refresh whose storage reads and writes must run somewhere. The
 * stores are built the way the facade builds them, with their default scope, so what is proved is
 * what ships. A store that waited for a thread of `Dispatchers.IO` would never be served; see
 * [IoSaturation] for why the deadline is a hard one.
 *
 * Its own file for the same reason: a regression here is a hang.
 */
class StorageIoSaturationTest {

    @get:Rule
    val folder: TemporaryFolder = TemporaryFolder()

    @Test
    fun `the credential store saves, reads, rotates and clears`() {
        val store = DataStoreCredentialStore(File(folder.newFolder(), "credentials"), ReversingKeyProvider())

        val seen = IoSaturation.start().use { io ->
            io.whileSaturated {
                store.save("first".toByteArray(), "id-token")
                val first = store.useRefreshToken { String(it) }
                store.replaceRefreshToken("second".toByteArray(), "id-token-2")
                val second = store.useRefreshToken { String(it) }
                val granted = store.hasGrant()
                store.clear()
                listOf(first, second, granted, store.hasGrant(), store.rawIdToken())
            }
        }

        assertEquals(listOf("first", "second", true, false, null), seen)
    }

    @Test
    fun `the pending authorization store saves, loads and clears`() {
        val store = FilePendingAuthorizationStore(File(folder.newFolder(), "pending-authorization"), ReversingKeyProvider())
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
