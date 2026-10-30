package versola.sdk.storage

import java.io.File
import java.io.IOException
import java.security.InvalidKeyException
import java.security.ProviderException
import java.security.UnrecoverableKeyException
import javax.crypto.AEADBadTagException
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.cancel
import kotlinx.coroutines.withContext
import kotlinx.coroutines.test.runTest
import versola.oauth.core.VersolaError
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
    fun `a ciphertext that fails authentication is a sign-out`() = runTest {
        store.save(refreshToken.toByteArray())
        keyProvider.unwrapFailure = AEADBadTagException("Tag mismatch")

        assertSignedOut { store.useRefreshToken { String(it) } }
    }

    @Test
    fun `a key that cannot be recovered is a sign-out`() = runTest {
        store.save(refreshToken.toByteArray())
        keyProvider.unwrapFailure = UnrecoverableKeyException("key entry is unreadable")

        assertSignedOut { store.useRefreshToken { String(it) } }
    }

    @Test
    fun `a permanent failure wrapped by the provider is still a sign-out`() = runTest {
        // Some providers wrap what the Keystore threw; the verdict is in the cause.
        store.save(refreshToken.toByteArray())
        keyProvider.unwrapFailure = IOException("unwrap failed", AEADBadTagException("Tag mismatch"))

        assertSignedOut { store.useRefreshToken { String(it) } }
    }

    @Test
    fun `every reader maps a permanent failure the same way`() = runTest {
        store.save(refreshToken.toByteArray(), idToken)
        store.savePendingRotation("idem-key-1")
        keyProvider.unwrapFailure = AEADBadTagException("Tag mismatch")

        assertSignedOut { store.rawIdToken() }
        assertSignedOut { store.pendingRotation() }
    }

    @Test
    fun `a failure that is no verdict on the key is recoverable and leaves the grant in place`() = runTest {
        // One OEM Keystore hiccup must not end the session: the grant is intact and the next
        // attempt will most likely open it.
        store.save(refreshToken.toByteArray(), idToken)
        val failures = listOf(
            IllegalStateException("Keystore operation failed"),
            ProviderException("Failed to communicate with the keystore service"),
            IOException("the keystore daemon is not ready"),
            InvalidKeyException("Keystore operation failed"),
        )

        for (failure in failures) {
            keyProvider.unwrapFailure = failure
            try {
                store.useRefreshToken { String(it) }
                fail("${failure.message}: an unreadable grant must not read as no grant")
            } catch (e: VersolaError.Recoverable) {
                assertTrue("${failure.message}: $e", e.reason is VersolaError.Recoverable.Cause.Network)
                assertSame(failure, e.cause)
            }
            assertTrue(store.hasGrant())
        }

        keyProvider.unwrapFailure = null
        assertEquals("the grant opens again once the key answers", refreshToken, store.useRefreshToken { String(it) })
        assertEquals(idToken, store.rawIdToken())
    }

    @Test
    fun `the cause names the failure class and nothing the failure said`() = runTest {
        // The message of a Keystore exception is the provider's to write; the error detail
        // that reaches an app's log carries the class alone.
        store.save(refreshToken.toByteArray())
        keyProvider.unwrapFailure = ProviderException("blob=$refreshToken")

        try {
            store.useRefreshToken { String(it) }
            fail("expected Recoverable")
        } catch (e: VersolaError.Recoverable) {
            assertFalse(e.toString().contains(refreshToken))
            assertEquals("storage key unavailable: ProviderException", (e.reason as VersolaError.Recoverable.Cause.Network).detail)
        }
    }

    @Test
    fun `a cancelled caller is a cancellation, not a sign-out`() = runTest {
        // The caller's scope was cancelled while the key was being used: nothing about the
        // grant changed, and reporting it as invalidated makes the coordinator wipe it.
        store.save(refreshToken.toByteArray())
        keyProvider.unwrapFailure = CancellationException("the caller's scope ended")

        try {
            store.useRefreshToken { String(it) }
            fail("cancellation must propagate")
        } catch (e: CancellationException) {
            assertEquals("the caller's scope ended", e.message)
        }
        assertTrue(store.hasGrant())
    }

    @Test
    fun `cancelling a caller suspended in the unwrap leaves the grant readable`() = runTest {
        store.save(refreshToken.toByteArray())
        val entered = CompletableDeferred<Unit>()
        keyProvider.onUnwrap = {
            entered.complete(Unit)
            awaitCancellation()
        }

        var thrown: Throwable? = null
        val caller = async(start = CoroutineStart.UNDISPATCHED) {
            try {
                store.useRefreshToken { String(it) }
            } catch (e: Throwable) {
                thrown = e
                throw e
            }
        }
        withContext(Dispatchers.Default) { entered.await() }
        caller.cancel()
        caller.join()

        // What the coordinator sees: a cancellation passes through and leaves the grant alone;
        // a sign-out would wipe it and destroy the DPoP key.
        assertTrue("the unwrap's cancellation reached the caller as itself: $thrown", thrown is CancellationException)
        keyProvider.onUnwrap = null
        assertEquals(refreshToken, store.useRefreshToken { String(it) })
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

    private suspend fun assertSignedOut(read: suspend () -> Unit) {
        try {
            read()
            fail("an unreadable grant must not read as no grant")
        } catch (e: VersolaError.Reauthenticate) {
            assertSame(VersolaError.Reauthenticate.Reason.CredentialsInvalidated, e.reason)
        }
    }

    // What 0.1.0 wrote has no record binding: the wrapped plaintext is the bare secret. A user
    // who upgrades must stay signed in, and the next save writes the bound form.

    private suspend fun writeLegacyFile(refresh: String?, id: String?, rotation: String?) {
        file.parentFile.mkdirs()
        file.writeBytes(
            CredentialBlob(
                refreshToken = refresh?.let { keyProvider.wrap(it.toByteArray()) },
                rawIdToken = id?.let { keyProvider.wrap(it.toByteArray()) },
                pendingRotation = rotation?.let { keyProvider.wrap(it.toByteArray()) },
            ).encode(),
        )
    }

    @Test
    fun `a grant written by 0 1 0 without record binding is still read`() = runTest {
        writeLegacyFile(refreshToken, idToken, "idem-key-1")

        assertTrue(store.hasGrant())
        assertEquals(refreshToken, store.useRefreshToken { String(it) })
        assertEquals(idToken, store.rawIdToken())
        assertEquals("idem-key-1", store.pendingRotation())
    }

    @Test
    fun `the next save rewrites a legacy grant bound to its slots, and it reads back`() = runTest {
        writeLegacyFile("old-refresh-token", idToken, null)

        store.save("rotated-refresh-token".toByteArray(), idToken)

        // What the key provider was handed is now sealed with the slot's name.
        val onDisk = CredentialBlob.decode(file.readBytes())
        val refreshPlaintext = keyProvider.unwrap(onDisk.refreshToken!!)
        assertTrue(String(refreshPlaintext, Charsets.ISO_8859_1).contains("credentials/refreshToken"))
        assertEquals("rotated-refresh-token", store.useRefreshToken { String(it) })
        assertEquals(idToken, store.rawIdToken())
    }

    @Test
    fun `a legacy ID token survives a refresh that rotates only the refresh token`() = runTest {
        writeLegacyFile("old-refresh-token", idToken, null)

        store.save("rotated-refresh-token".toByteArray(), null)

        assertEquals("rotated-refresh-token", store.useRefreshToken { String(it) })
        assertEquals("the legacy ID token is kept as it was", idToken, store.rawIdToken())
    }

    @Test
    fun `a blob moved to another slot does not open there`() = runTest {
        // A valid wrapped ID token placed in the refresh token's field: without the binding it
        // would be sent to the token endpoint as a refresh token.
        store.save(refreshToken.toByteArray(), idToken)
        val onDisk = CredentialBlob.decode(file.readBytes())
        val moved = File(folder.newFolder(), "credentials")
        moved.writeBytes(CredentialBlob(refreshToken = onDisk.rawIdToken, rawIdToken = onDisk.refreshToken).encode())
        val swapped = DataStoreCredentialStore(moved, keyProvider, scope)

        assertSignedOut { swapped.useRefreshToken { String(it) } }
        assertSignedOut { swapped.rawIdToken() }
    }

    @Test
    fun `a sealed record that is cut short is read as tampered, not as a token`() = runTest {
        file.parentFile.mkdirs()
        file.writeBytes(CredentialBlob(refreshToken = keyProvider.wrap(byteArrayOf(0, 'V'.code.toByte(), 'B'.code.toByte(), 2, 40))).encode())

        assertSignedOut { store.useRefreshToken { String(it) } }
    }
}
