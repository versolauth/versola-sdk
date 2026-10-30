package versola.oauth.core

import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * What [SdkDispatchers] promises, shown rather than assumed: the views make progress while an app
 * holds every thread of `Dispatchers.IO`, they are not capped by its 64 threads, and the two do not
 * share a quota. In its own file with [IoSaturation]'s hard deadlines for the reason that file gives.
 */
class SdkDispatchersTest {

    @Test
    fun `the SDK's work runs while every thread of IO is held`() {
        val ran = IoSaturation.start().use { io ->
            io.whileSaturated { withContext(SdkDispatchers.blocking) { Thread.currentThread().name } }
        }

        assertFalse(ran.isEmpty())
    }

    @Test
    fun `a full quota of the SDK's tasks is in flight at once beside a saturated IO`() {
        // 64 tasks that each wait for the others: they can only finish if all 64 run concurrently,
        // which is the quota of the view and more than the default view of IO would ever give beside
        // the callers that already hold it.
        val concurrent = 64
        val allRunning = CountDownLatch(concurrent)

        IoSaturation.start().use { io ->
            io.whileSaturated {
                coroutineScope {
                    List(concurrent) {
                        async(SdkDispatchers.blocking) {
                            allRunning.countDown()
                            check(allRunning.await(15, TimeUnit.SECONDS)) { "the view did not run $concurrent tasks at once" }
                        }
                    }.awaitAll()
                }
            }
        }
    }

    @Test
    fun `callers parked on the calls view leave the SDK's view its threads`() {
        // What OAuthClient.call() does: 64 calls park a thread each on `blockedCalls`, and the work
        // they wait for runs on `blocking`. Were it the same view, the 64 would take its whole quota.
        val parked = CountDownLatch(64)
        val release = CountDownLatch(1)
        val waiting = Thread {
            runBlocking {
                List(64) {
                    async(SdkDispatchers.blockedCalls) {
                        parked.countDown()
                        release.await()
                    }
                }.awaitAll()
            }
        }.apply { isDaemon = true }
        waiting.start()
        try {
            assertTrue("the 64 calls never all parked", parked.await(15, TimeUnit.SECONDS))

            val ran = IoSaturation.start().use { io ->
                io.whileSaturated { withContext(SdkDispatchers.blocking) { true } }
            }

            assertTrue(ran)
        } finally {
            release.countDown()
            waiting.join(15_000)
        }
    }

    @Test
    fun `the SDK's view and the calls view are two views of IO, not IO itself`() {
        assertNotSame(SdkDispatchers.blocking, SdkDispatchers.blockedCalls)
        assertNotSame(Dispatchers.IO, SdkDispatchers.blocking)
        assertNotSame(Dispatchers.IO, SdkDispatchers.blockedCalls)
    }

    /**
     * The rule the saturation tests rest on, held for every module whose main sources do the SDK's
     * blocking work: `Dispatchers.IO` is named nowhere but in [SdkDispatchers] itself. A new site
     * that dispatched to it would put the refresh back in line behind the app's own callers.
     * `:core` and `:sdk` (the Versola facade) are not scanned: they have not been moved.
     */
    @Test
    fun `no main source of the generic modules dispatches to Dispatchers IO`() {
        val modules = listOf("oauth-core", "storage", "dpop", "oauth", "okhttp")
        val root = File("..").canonicalFile
        val sources = modules.flatMap { module ->
            File(root, "$module/src/main").walkTopDown().filter { it.isFile && it.extension == "kt" }.toList()
        }
        assertTrue("the scan found no sources: is the working directory the module's own?", sources.size > 20)

        val offenders = sources
            .filterNot { it.name == "SdkDispatchers.kt" }
            .filter { DirectIoScan.dispatchesToIo(it.readText()) }
            .map { it.relativeTo(root).path }

        assertTrue(
            "blocking SDK work goes through SdkDispatchers.blocking, never Dispatchers.IO:\n${offenders.joinToString("\n")}",
            offenders.isEmpty(),
        )
    }

    @Test
    fun `the scan sees a direct use of IO however it is spelled`() {
        listOf(
            "withContext(Dispatchers.IO) { work() }",
            "withContext(Dispatchers\n    .IO) { work() }",
            "withContext(kotlinx.coroutines.Dispatchers.IO) { work() }",
            "withContext(Dispatchers .\n IO) { work() }",
            "import kotlinx.coroutines.Dispatchers.IO\nfun f() = withContext(IO) { }",
            "import kotlinx.coroutines.Dispatchers.*\nfun f() = withContext(IO) { }",
            "import kotlinx.coroutines.Dispatchers as D\nfun f() = withContext(D.IO) { }",
            "val x = 1 // fine\nval d = CoroutineScope(Dispatchers.IO + SupervisorJob())",
            "val url = \"https://example.com\"; val d = Dispatchers.IO",
        ).forEach { assertTrue("not seen: $it", DirectIoScan.dispatchesToIo(it)) }
    }

    @Test
    fun `the scan leaves comments and other dispatchers alone`() {
        listOf(
            "// withContext(Dispatchers.IO) is what this does not do",
            "/** Not on `Dispatchers.IO`: see [SdkDispatchers]. */\nfun f() {}",
            "/*\n * Dispatchers\n * .IO is named here in prose\n */",
            "val d = Dispatchers.Default",
            "val d = Dispatchers.IOExecutor",
            "import kotlinx.coroutines.Dispatchers\nval d = Dispatchers.Default",
            "val d = SdkDispatchers.blocking",
            "val d = MyDispatchers.IO",
        ).forEach { assertFalse("seen where there is none: $it", DirectIoScan.dispatchesToIo(it)) }
    }
}

/**
 * Whether a Kotlin source dispatches to `Dispatchers.IO`: the whole text, comments removed, not line
 * by line, so a `Dispatchers` and its `.IO` split over two lines are still one use; and an import of
 * `Dispatchers.IO`, of `Dispatchers.*` or of `Dispatchers` under another name is a use too, because
 * a bare `IO` or an alias then needs no `Dispatchers.IO` in the text at all.
 */
internal object DirectIoScan {
    private val blockComment = Regex("/\\*[\\s\\S]*?\\*/")
    private val lineComment = Regex("(?m)(^|\\s)//[^\\n]*")
    private val direct = Regex("(?<!\\w)Dispatchers\\s*\\.\\s*IO\\b")
    private val importOfIo = Regex("import\\s+kotlinx\\.coroutines\\.Dispatchers\\s*\\.\\s*(IO\\b|\\*)")
    private val importAlias = Regex("import\\s+kotlinx\\.coroutines\\.Dispatchers\\s+as\\b")

    fun dispatchesToIo(source: String): Boolean {
        val code = source.replace(blockComment, " ").replace(lineComment, "$1")
        return direct.containsMatchIn(code) || importOfIo.containsMatchIn(code) || importAlias.containsMatchIn(code)
    }
}
