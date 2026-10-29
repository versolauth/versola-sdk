package versola.oauth

import android.util.Log
import versola.oauth.core.VersolaLogger

/**
 * The default logger: warnings to logcat, nothing else. No line the SDK emits through it
 * carries a token, code, verifier, `state`, `nonce` or claim value (`spec/oauth-sdk-api.md`
 * section 15); what this class controls is only where the lines go.
 */
public class LogcatLogger(private val tag: String = "OAuth") : VersolaLogger {
    override fun info(message: String) {
        Log.i(tag, message)
    }

    override fun warn(message: String) {
        Log.w(tag, message)
    }
}
