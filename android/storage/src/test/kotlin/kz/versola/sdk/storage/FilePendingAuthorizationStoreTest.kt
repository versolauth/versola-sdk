package kz.versola.sdk.storage

import java.io.File
import kotlinx.coroutines.test.runTest
import kz.versola.sdk.core.PendingAuthorizationCodec
import kz.versola.sdk.core.PendingAuthorizationRequest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
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
    fun `a slot that cannot be unwrapped is discarded rather than surfaced`() = runTest {
        // The user logs in again. Nothing is recoverable from a slot that will not open, and
        // failing loudly here would brick login on a key rotation.
        store.save(request)
        keyProvider.unwrapFailure = IllegalStateException("key no longer decrypts this")

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
