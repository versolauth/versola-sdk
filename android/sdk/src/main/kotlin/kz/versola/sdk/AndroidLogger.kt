package kz.versola.sdk

import android.util.Log
import kz.versola.sdk.core.VersolaLogger

/**
 * The default sink for the SDK's warnings. Nothing credential-shaped is ever passed to a
 * logger — scenario 01 asserts no access token appears in any log the SDK emits at its
 * default level, and the same rule covers verifiers, codes and refresh tokens.
 */
public class AndroidLogger(
    private val tag: String = "Versola",
) : VersolaLogger {

    override fun info(message: String) {
        Log.i(tag, message)
    }

    override fun warn(message: String) {
        Log.w(tag, message)
    }
}
