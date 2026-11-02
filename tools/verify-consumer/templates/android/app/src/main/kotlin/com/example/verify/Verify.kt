package com.example.verify

import android.content.Context
import okhttp3.OkHttpClient
import versola.oauth.OAuthClient
import versola.oauth.OAuthConfiguration
import versola.oauth.core.VersolaError
import versola.sdk.browser.VersolaRedirectActivity
import versola.sdk.dpop.KeyAttestation

// Never run: the build is the test. The SDK is one artefact whose AAR is merged from several build
// modules, so each line names a type that came from a different one: the compiler has to find all
// of them in the one AAR.

// oauth-android: the facade and its configuration. VersolaError is oauth-core's (the error
// taxonomy), which the facade's signatures expose.
internal fun configuration(): OAuthConfiguration = OAuthConfiguration(
    issuer = "https://id.example.com",
    clientId = "verify-consumer",
    redirectUri = "https://app.example.com/oauth",
)

internal fun client(context: Context): OAuthClient = try {
    OAuthClient.create(context, configuration())
} catch (error: VersolaError) {
    throw IllegalStateException("configuration refused", error)
}

// okhttp-android: OkHttpClient is OkHttp's, which the facade's authenticatedClient() returns.
internal fun http(client: OAuthClient): OkHttpClient = client.authenticatedClient()

// dpop's KeyAttestation (on the facade's ABI) and browser's redirect activity, which the app's
// manifest re-declares: both are in the one AAR.
internal val tiers: List<KeyAttestation> = KeyAttestation.entries
internal val redirectActivity: Class<out android.app.Activity> = VersolaRedirectActivity::class.java
