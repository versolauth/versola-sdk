package versola.sdk.dpop

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The DPoP key while an app holds every thread of `Dispatchers.IO`: 80 callers parked in a blocking
 * `execute()`, each waiting for a refresh whose token request needs a proof, and the proof needs the
 * Keystore key generated, loaded and asked to sign. The key's generation, its signature and its
 * destruction on logout all have to be served without a thread of `Dispatchers.IO`.
 *
 * Its own class because a regression is a hang, which would stall the whole instrumentation run;
 * [IoSaturation] puts a hard deadline on each case.
 */
@RunWith(AndroidJUnit4::class)
class DpopKeyIoSaturationInstrumentedTest {

    private val alias = "versola.test.dpop-key-saturated"

    @Before
    @After
    fun clean() {
        KeystoreDpopKey.destroy(alias)
    }

    @Test
    fun theKeyIsGeneratedAndSignsWhileIoIsSaturated() {
        val key = KeystoreDpopKey(alias)

        val proof = IoSaturation.start().use { io ->
            // The first use generates the key, in StrongBox when there is one, then signs with it.
            io.whileSaturated { DpopProofFactory(key).proof("POST", "https://id.example.com/token") }
        }

        assertEquals(3, proof.split('.').size)
    }

    @Test
    fun destroyingTheKeyRegeneratesItWhileIoIsSaturated() {
        val key = KeystoreDpopKey(alias)

        val thumbprints = IoSaturation.start().use { io ->
            io.whileSaturated {
                val before = key.jkt()
                key.destroy()
                before to key.jkt()
            }
        }

        assertTrue(thumbprints.first.isNotEmpty())
        assertNotEquals("a destroyed key is replaced by a new one", thumbprints.first, thumbprints.second)
    }
}
