package com.example.verify

import android.content.Context
import okhttp3.OkHttpClient
import versola.oauth.OAuthClient
import versola.oauth.OAuthConfiguration
import versola.oauth.core.VersolaError

// Never run: the build is the test. Each line names a type from a different published module, so
// the compiler has to open every artefact the dependency pulled in.

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
