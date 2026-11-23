package versola.sdk.core

import java.io.File
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import versola.oauth.core.VersolaError

/**
 * `FileNativeEndpointsStore`: what the refresh that follows a login signs for. Its failures are
 * typed like the credential store's (`Recoverable(Network)`: grant intact, may be repeated), a file
 * it did not write is deleted, and a read that merely failed is never taken for one.
 */
class FileNativeEndpointsStoreTest {

    @get:Rule
    val folder = TemporaryFolder()

    private val endpoints = NativeEndpoints("https://id.example.com:9008/token", "https://id.example.com:9008/revoke")

    private fun assertNetworkFailure(error: Throwable) {
        val recoverable = error as? VersolaError.Recoverable ?: throw AssertionError("not Recoverable: $error")
        assertTrue(recoverable.reason.toString(), recoverable.reason is VersolaError.Recoverable.Cause.Network)
    }

    @Test
    fun `what was saved is loaded back, and nothing is there before`() = runTest {
        val store = FileNativeEndpointsStore(File(folder.newFolder(), "endpoints.json"))

        assertNull(store.load())
        store.save(endpoints)

        assertEquals(endpoints, store.load())
    }

    @Test
    fun `a file that is not what the store writes is deleted and reads as nothing`() = runTest {
        val file = File(folder.newFolder(), "endpoints.json").apply { writeText("not json") }

        assertNull(FileNativeEndpointsStore(file).load())

        assertFalse(file.exists())
    }

    @Test
    fun `a read that fails is raised and leaves the file, so one transient error does not end the session`() = runTest {
        // A directory where the file should be: it exists, and reading it is an I/O error, not a decode error.
        val file = File(folder.newFolder(), "endpoints.json").apply { mkdir() }

        val error = failure { FileNativeEndpointsStore(file).load() }

        assertNetworkFailure(error)
        assertTrue("the unreadable entry was not deleted", file.exists())
    }

    @Test
    fun `a failed rename is a failure, and the temporary file is not left behind`() = runTest {
        val directory = folder.newFolder()
        // A non-empty directory in the destination's place: the rename of a file onto it fails.
        val file = File(directory, "endpoints.json").apply { mkdir() }
        File(file, "occupied").writeText("x")

        val error = failure { FileNativeEndpointsStore(file).save(endpoints) }

        assertNetworkFailure(error)
        assertFalse(File(directory, "endpoints.json.tmp").exists())
    }

    @Test
    fun `a write that fails is typed, not an IOException`() = runTest {
        // The parent is a regular file, so neither the directory nor the file can be created.
        val parent = folder.newFile("not-a-directory")

        val error = failure { FileNativeEndpointsStore(File(parent, "endpoints.json")).save(endpoints) }

        assertNetworkFailure(error)
    }
}
