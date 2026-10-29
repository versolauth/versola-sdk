package versola.sdk.storage

import android.security.keystore.KeyProperties
import versola.oauth.core.UnlockPolicy
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * The key's authentication parameters, which decide how often a user sees a prompt. The
 * Keystore has no JVM implementation, so generation itself is out of reach here; what the key
 * is *asked* for is not, and that is where the policy decision lives.
 */
@RunWith(RobolectricTestRunner::class)
class HardwareKeyProviderTest {

    @Test
    fun `default policy does not gate the key`() {
        val spec = HardwareKeyProvider.keySpec("alias", UnlockPolicy.None)

        assertFalse(spec.isUserAuthenticationRequired)
    }

    @Test
    fun `OnAppUnlock gates the key for a window rather than per operation`() {
        val spec = HardwareKeyProvider.keySpec("alias", UnlockPolicy.OnAppUnlock)

        assertTrue(spec.isUserAuthenticationRequired)
        // Zero would mean auth-per-use: a prompt for every token request.
        assertEquals(300, spec.userAuthenticationValidityDurationSeconds)
        assertEquals(
            KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
            spec.userAuthenticationType,
        )
    }

    @Test
    @Config(sdk = [29])
    fun `the same window is expressed below API 30`() {
        val spec = HardwareKeyProvider.keySpec("alias", UnlockPolicy.OnAppUnlock)

        assertTrue(spec.isUserAuthenticationRequired)
        assertEquals(300, spec.userAuthenticationValidityDurationSeconds)
    }

    @Test
    fun `the window matches the cross-platform constant`() {
        // iOS cannot exceed 300s; a divergence here would be two machines, not one.
        assertEquals(
            UnlockPolicy.UNLOCK_WINDOW_SECONDS,
            HardwareKeyProvider.keySpec("alias", UnlockPolicy.OnAppUnlock)
                .userAuthenticationValidityDurationSeconds,
        )
    }
}
