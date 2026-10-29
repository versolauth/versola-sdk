package kz.versola.sdk.storage

import java.io.File
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.test.runTest
import kz.versola.sdk.core.VersolaError
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class DataStoreCredentialStoreTest {

    @get:Rule
    val folder: TemporaryFolder = TemporaryFolder()

    private lateinit var file: File
    private lateinit var keyProvider: ReversingKeyProvider
    private lateinit var scope: CoroutineScope
    private lateinit var store: DataStoreCredentialStore

    private val refreshToken = "8xLOxBtZp8-refresh-token-value"
    private val idToken = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.sig"

    @Before
    fun setUp() {
        file = File(folder.newFolder(), "credentials")
        keyProvider = ReversingKeyProvider()
        // DataStore's own scope, not the test's: its writes outlive the call that started
        // them, and cancelling them at the end of runTest would be cancelling the store.
        scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
        store = DataStoreCredentialStore(file, keyProvider, scope)
    }

    @After
    fun tearDown() {
        scope.cancel()
    }

    @Test
    fun `a saved refresh token comes back byte-identical`() = runTest {
        store.save(refreshToken.toByteArray(), idToken)

        val seen = store.useRefreshToken { String(it) }

        assertEquals(refreshToken, seen)
        assertEquals(idToken, store.rawIdToken())
    }

    @Test
    fun `the buffer handed out is zeroed once the block ends`() = runTest {
        store.save(refreshToken.toByteArray())

        // Kept deliberately: the point is that the array the block saw is no longer readable
        // after it returned, which is the whole of "unwrapped for one request and no longer".
        var escaped: ByteArray? = null
        store.useRefreshToken { escaped = it }

        assertArrayEquals(ByteArray(refreshToken.length), escaped)
    }

    @Test
    fun `the buffer is zeroed even when the block throws`() = runTest {
        store.save(refreshToken.toByteArray())

        var escaped: ByteArray? = null
        try {
            store.useRefreshToken<Unit> { escaped = it; error("the token request failed") }
            fail("the block's failure should reach the caller")
        } catch (e: IllegalStateException) {
            assertEquals("the token request failed", e.message)
        }

        assertArrayEquals(ByteArray(refreshToken.length), escaped)
    }

    @Test
    fun `save takes ownership and zeroes the caller's array`() = runTest {
        val caller = refreshToken.toByteArray()

        store.save(caller)

        assertArrayEquals(ByteArray(refreshToken.length), caller)
    }

    @Test
    fun `save zeroes the caller's array even when wrap throws`() = runTest {
        // A locked key above all: `save` owns the buffer regardless of whether the wrap it
        // was handed to succeeds, so a failed save must not leave it readable.
        val caller = refreshToken.toByteArray()
        keyProvider.wrapFailure = IllegalStateException("the key is locked")

        try {
            store.save(caller)
            fail("wrap's failure should reach the caller")
        } catch (e: IllegalStateException) {
            assertEquals("the key is locked", e.message)
        }

        assertArrayEquals(ByteArray(refreshToken.length), caller)
    }

    @Test
    fun `the plaintext never reaches the disk`() = runTest {
        store.save(refreshToken.toByteArray(), idToken)
        store.savePendingRotation("idem-key-1")

        val onDisk = file.readText(Charsets.ISO_8859_1)

        assertFalse(onDisk.contains(refreshToken))
        assertFalse(onDisk.contains(idToken))
        assertFalse(onDisk.contains("idem-key-1"))
    }

    @Test
    fun `whether a grant exists is answerable without the key`() = runTest {
        // A cold start decides Authenticated or Unauthenticated before the app spends the
        // grant. Under UnlockPolicy.OnAppUnlock, needing the key here would be a prompt on
        // every launch.
        store.save(refreshToken.toByteArray())
        keyProvider.unwrapFailure = IllegalStateException("the key was not consulted")

        assertTrue(store.hasGrant())
    }

    @Test
    fun `no grant reads as no grant rather than as an error`() = runTest {
        assertFalse(store.hasGrant())
        assertNull(store.useRefreshToken { String(it) })
        assertNull(store.rawIdToken())
        assertNull(store.pendingRotation())
    }

    @Test
    fun `a refresh that omits the ID token leaves the stored one in place`() = runTest {
        // OIDC permits a refresh response without id_token, and id_token_hint at logout wants
        // the last one known rather than none.
        store.save(refreshToken.toByteArray(), idToken)

        store.save("rotated".toByteArray())

        assertEquals(idToken, store.rawIdToken())
        assertEquals("rotated", store.useRefreshToken { String(it) })
    }

    @Test
    fun `the rotation slot is written and cleared independently of the grant`() = runTest {
        store.save(refreshToken.toByteArray())

        store.savePendingRotation("idem-key-1")
        assertEquals("idem-key-1", store.pendingRotation())

        // Step 3: cleared after the response is durably stored, and the grant is untouched.
        store.savePendingRotation(null)

        assertNull(store.pendingRotation())
        assertTrue(store.hasGrant())
    }

    @Test
    fun `clear leaves nothing behind`() = runTest {
        store.save(refreshToken.toByteArray(), idToken)
        store.savePendingRotation("idem-key-1")

        store.clear()

        assertFalse(store.hasGrant())
        assertNull(store.rawIdToken())
        assertNull(store.pendingRotation())
        assertFalse(file.readText(Charsets.ISO_8859_1).contains(refreshToken.reversed()))
    }

    @Test
    fun `a grant that will not unwrap is a sign-out`() = runTest {
        store.save(refreshToken.toByteArray())
        keyProvider.unwrapFailure = IllegalStateException("key no longer decrypts this")

        try {
            store.useRefreshToken { String(it) }
            fail("an unreadable grant must not read as no grant")
        } catch (e: VersolaError.Reauthenticate) {
            assertSame(VersolaError.Reauthenticate.Reason.CredentialsInvalidated, e.reason)
        }
    }

    @Test
    fun `a locked key is passed through as itself, not as a sign-out`() = runTest {
        // The difference the app acts on: prompt and retry, versus send the user to login().
        store.save(refreshToken.toByteArray())
        keyProvider.unwrapFailure = VersolaError.Recoverable(
            VersolaError.Recoverable.Cause.UnlockRequired,
        )

        try {
            store.useRefreshToken { String(it) }
            fail("a locked key must not be reported as an invalidated grant")
        } catch (e: VersolaError.Recoverable) {
            assertSame(VersolaError.Recoverable.Cause.UnlockRequired, e.reason)
        }
        assertTrue(store.hasGrant())
    }

    @Test
    fun `a file that is not a credential file reads as no grant`() = runTest {
        // Its own file and its own store: DataStore permits exactly one instance per file.
        val corrupt = File(folder.newFolder(), "credentials")
        corrupt.writeBytes(byteArrayOf(1, 2, 3))

        assertFalse(DataStoreCredentialStore(corrupt, keyProvider, scope).hasGrant())
    }

    @Test
    fun `a forged field length near Int MAX VALUE reads as no grant rather than wedging the store`() = runTest {
        // offset (3, after magic + version) + this length overflows a signed Int to a
        // negative number. The old bounds check read that as "within range" and reached
        // `copyOfRange` with a corrupt range, which throws `IllegalArgumentException` — not
        // `CorruptionException` — so DataStore never resets the file and every later call
        // throws instead of reading as no grant.
        val corrupt = File(folder.newFolder(), "credentials")
        corrupt.writeBytes(
            byteArrayOf('V'.code.toByte(), 'C'.code.toByte(), 1, 0x7F, 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte()),
        )

        assertFalse(DataStoreCredentialStore(corrupt, keyProvider, scope).hasGrant())
    }

    @Test
    fun `forFile hands back the one store already open on a path`() = runTest {
        val shared = File(folder.newFolder(), "credentials")

        val first = DataStoreCredentialStore.forFile(shared, keyProvider)
        val second = DataStoreCredentialStore.forFile(File(shared.parentFile, "./credentials"), keyProvider)

        // A second DataStore over the same file throws on its first read; a second
        // configure() in a process must not get one.
        assertSame(first, second)
        first.save("token".toByteArray(), null)
        assertTrue(second.hasGrant())
    }
}
