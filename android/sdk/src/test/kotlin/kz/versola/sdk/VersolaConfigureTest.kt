package kz.versola.sdk

import android.app.Application
import androidx.test.core.app.ApplicationProvider
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import kz.versola.sdk.core.SessionState
import kz.versola.sdk.core.VersolaError
import kz.versola.sdk.core.VersolaLogger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

private class CollectingLogger : VersolaLogger {
    val warnings = mutableListOf<String>()
    val info = mutableListOf<String>()

    override fun info(message: String) {
        info += message
    }

    override fun warn(message: String) {
        warnings += message
    }
}

@RunWith(RobolectricTestRunner::class)
class VersolaConfigureTest {

    private val application = ApplicationProvider.getApplicationContext<Application>()

    private fun configure(
        issuer: String = "https://id.versola.kz",
        clientId: String = "mobile-app",
        redirectUri: String = "https://app.example.com/oauth",
        logger: VersolaLogger = CollectingLogger(),
    ) = Versola.configure(application, issuer, clientId, redirectUri, logger)

    @Test
    fun `configure keeps the validated configuration`() {
        val versola = configure()

        assertEquals("https://id.versola.kz", versola.configuration.issuer)
        assertEquals("mobile-app", versola.configuration.clientId)
        assertEquals("https://app.example.com/oauth", versola.configuration.redirectUri.value)
    }

    @Test
    fun `a private-use redirect scheme warns on the spot`() {
        // #5 asks for this to be loud, because the alternative is discovering on a support
        // ticket that another app claimed the scheme.
        val logger = CollectingLogger()

        configure(redirectUri = "com.example.app:/oauth", logger = logger)

        assertEquals(1, logger.warnings.size)
        assertTrue(logger.warnings.single().contains("private-use scheme"))
    }

    @Test
    fun `an App Link redirect warns about nothing`() {
        val logger = CollectingLogger()

        configure(logger = logger)

        assertTrue(logger.warnings.isEmpty())
    }

    @Test
    fun `a bad issuer fails at configure time rather than behind a login screen`() {
        assertThrows(VersolaError.Configuration::class.java) { configure(issuer = "http://id.versola.kz") }
        assertThrows(VersolaError.Configuration::class.java) { configure(clientId = "") }
        assertThrows(VersolaError.Configuration::class.java) { configure(redirectUri = "/relative") }
    }

    @Test
    fun `a fresh install starts Unauthenticated`() = runTest {
        assertSame(SessionState.Unauthenticated, configure().sessionState.first())
    }
}
