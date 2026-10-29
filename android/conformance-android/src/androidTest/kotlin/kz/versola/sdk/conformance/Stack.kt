package kz.versola.sdk.conformance

import androidx.test.platform.app.InstrumentationRegistry

/**
 * Where the staged stack is, from the device's point of view, and the credentials the
 * reference client (`e2e/.../support/E2EConfig.scala`) uses for the same stack. The defaults
 * are gen-env's `local` target reached through `adb reverse`, so the issuer the SDK validates
 * is exactly the one auth announces.
 *
 * Overridden per run with instrumentation arguments:
 * `-Pandroid.testInstrumentationRunnerArguments.authUrl=http://10.0.2.2:9003`.
 */
class Stack private constructor(
    val authUrl: String,
    val centralUrl: String,
    val edgeUrl: String,
    /** Central's management API: Basic `central:<resource secret>`, as `CentralApi.live`. */
    val centralSecret: String,
    /** Edge's internal API: Basic `edge:<internal secret>`, as `OAuthClient.edgeAuthorization`. */
    val edgeInternalSecret: String,
    /** Where edge reaches the upstream MockWebServer this driver runs: the host side of `adb forward`. */
    val upstreamUrlFromEdge: String,
    val upstreamPort: Int,
) {
    companion object {
        fun fromArguments(): Stack {
            val args = InstrumentationRegistry.getArguments()
            fun arg(name: String, default: String) = args.getString(name)?.takeIf { it.isNotBlank() } ?: default
            val upstreamPort = arg("upstreamPort", "18080").toInt()
            return Stack(
                authUrl = arg("authUrl", "http://localhost:9003").trimEnd('/'),
                centralUrl = arg("centralUrl", "http://localhost:9001").trimEnd('/'),
                edgeUrl = arg("edgeUrl", "http://localhost:9005").trimEnd('/'),
                centralSecret = arg("centralSecret", "ZGV2LWNlbnRyYWwtYWRtaW4tc2VjcmV0LTMyYnl0ZXM"),
                edgeInternalSecret = arg("edgeInternalSecret", "ZGV2LWVkZ2UtaW50ZXJuYWwtc2VjcmV0LTMyYnl0ZSE"),
                upstreamUrlFromEdge = arg("upstreamUrlFromEdge", "http://localhost:$upstreamPort"),
                upstreamPort = upstreamPort,
            )
        }
    }
}
