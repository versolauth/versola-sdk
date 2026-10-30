package versola.sdk.storage

import java.io.File
import java.security.ProviderException
import java.security.UnrecoverableKeyException
import javax.crypto.AEADBadTagException
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.test.runTest
import versola.oauth.core.VersolaError
import versola.oauth.core.PendingAuthorizationCodec
import versola.oauth.core.PendingAuthorizationRequest
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

class FilePendingAuthorizationStoreTest {

    @get:Rule
    val folder: TemporaryFolder = TemporaryFolder()

    private lateinit var file: File
    private lateinit var keyProvider: ReversingKeyProvider
    private lateinit var store: FilePendingAuthorizationStore

    private val verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

    private val request = PendingAuthorizationRequest(
        state = "the-state",
        nonce = "the-nonce",
        codeVerifier = verifier,
        scopes = listOf("openid", "profile"),
        redirectUri = "https://app.example.com/oauth",
        acrValues = listOf("phr"),
        maxAge = 300,
        createdAtEpochMillis = 1_700_000_000_000,
    )

    @Before
    fun setUp() {
        file = File(folder.newFolder(), "pending-authorization")
        keyProvider = ReversingKeyProvider()
        store = FilePendingAuthorizationStore(file, keyProvider)
    }

    @Test
    fun `a saved request comes back whole`() = runTest {
        store.save(request)

        val restored = store.load()!!

        assertEquals(request.state, restored.state)
        assertEquals(request.nonce, restored.nonce)
        assertEquals(request.scopes, restored.scopes)
        assertEquals(request.redirectUri, restored.redirectUri)
        assertEquals(request.acrValues, restored.acrValues)
        assertEquals(request.maxAge, restored.maxAge)
        assertEquals(request.createdAtEpochMillis, restored.createdAtEpochMillis)
        // The code_verifier is not readable from here by design, so fidelity is asserted on
        // the encoding instead — which is what the exchange will read it back out of.
        assertArrayEquals(
            PendingAuthorizationCodec.encode(request),
            PendingAuthorizationCodec.encode(restored),
        )
    }

    @Test
    fun `the plaintext never reaches the disk`() = runTest {
        store.save(request)

        val onDisk = file.readText(Charsets.ISO_8859_1)

        assertFalse(onDisk.contains(verifier))
        assertFalse(onDisk.contains(request.state))
    }

    @Test
    fun `nothing pending reads as nothing pending`() = runTest {
        assertNull(store.load())
    }

    @Test
    fun `there is one slot, and a second login replaces it`() = runTest {
        store.save(request)
        store.save(
            PendingAuthorizationRequest(
                state = "second",
                nonce = "second",
                codeVerifier = "second",
                scopes = listOf("openid"),
                redirectUri = "https://app.example.com/oauth",
                acrValues = emptyList(),
                maxAge = null,
                createdAtEpochMillis = 2,
            ),
        )

        assertEquals("second", store.load()!!.state)
    }

    @Test
    fun `clear leaves nothing behind`() = runTest {
        store.save(request)

        store.clear()

        assertNull(store.load())
        assertFalse(file.exists())
    }

    @Test
    fun `a slot whose key is gone for good is discarded rather than surfaced`() = runTest {
        // The user logs in again. Nothing is recoverable from a slot that will never open, and
        // failing loudly here would brick login on a key rotation.
        for (failure in listOf(
            AEADBadTagException("Tag mismatch"),
            UnrecoverableKeyException("key entry is unreadable"),
            VersolaError.Reauthenticate(VersolaError.Reauthenticate.Reason.CredentialsInvalidated),
        )) {
            store.save(request)
            keyProvider.unwrapFailure = failure

            assertNull("$failure", store.load())
            assertFalse("$failure", file.exists())
        }
    }

    @Test
    fun `a locked key keeps the slot and says so`() = runTest {
        // The login the user is in the middle of is intact; deleting it because the unlock
        // window elapsed would lose an authorization whose redirect is on its way.
        store.save(request)
        keyProvider.unwrapFailure = VersolaError.Recoverable(VersolaError.Recoverable.Cause.UnlockRequired)

        try {
            store.load()
            fail("a locked key must not read as nothing pending")
        } catch (e: VersolaError.Recoverable) {
            assertSame(VersolaError.Recoverable.Cause.UnlockRequired, e.reason)
        }
        assertTrue(file.exists())

        keyProvider.unwrapFailure = null
        assertEquals(request.state, store.load()!!.state)
    }

    @Test
    fun `a transient keystore failure keeps the slot and is recoverable`() = runTest {
        store.save(request)
        keyProvider.unwrapFailure = ProviderException("Failed to communicate with the keystore service")

        try {
            store.load()
            fail("a keystore hiccup must not read as nothing pending")
        } catch (e: VersolaError.Recoverable) {
            assertTrue(e.reason is VersolaError.Recoverable.Cause.Network)
        }
        assertTrue(file.exists())

        keyProvider.unwrapFailure = null
        assertEquals(request.state, store.load()!!.state)
    }

    @Test
    fun `a cancelled caller is a cancellation and leaves the slot`() = runTest {
        store.save(request)
        keyProvider.unwrapFailure = CancellationException("the caller's scope ended")

        try {
            store.load()
            fail("cancellation must propagate")
        } catch (e: CancellationException) {
            assertEquals("the caller's scope ended", e.message)
        }
        assertTrue(file.exists())
    }

    @Test
    fun `a slot that authenticates but does not decode is discarded`() = runTest {
        // The plaintext opened, so the key is fine; what it holds is not a pending request.
        // Nothing will ever make it one.
        file.parentFile.mkdirs()
        file.writeBytes(keyProvider.wrap("not json".toByteArray()))

        assertNull(store.load())
        assertFalse(file.exists())
    }

    @Test
    fun `a truncated file is discarded rather than surfaced`() = runTest {
        file.parentFile.mkdirs()
        file.writeBytes(byteArrayOf(1, 2, 3))

        assertNull(store.load())
        assertFalse(file.exists())
    }

    @Test
    fun `no temporary file survives a save`() = runTest {
        // The write goes to a sibling and is renamed, so a process killed mid-write cannot
        // leave a half-written slot — which would defeat the point of persisting at all.
        store.save(request)

        assertTrue(file.exists())
        assertFalse(File(file.parentFile, file.name + ".tmp").exists())
    }
}
