// The protocol core: discovery, PKCE, authorization request and response, the token client,
// the session coordinator, the retry budget, the error taxonomy, and the seams a facade plugs
// into (the browser, the stores, the DPoP proof source, the authorization starter). Plain
// Kotlin/JVM with no android.* import, so it compiles and tests without AGP and can be shared
// (ADR 0001). Nothing in here names Versola, edge, a tenant or a security profile; the Versola
// facade's own half lives in :core.
plugins {
    id("org.jetbrains.kotlin.jvm")
    id("org.jetbrains.kotlin.plugin.serialization")
    id("org.jetbrains.kotlinx.binary-compatibility-validator")
}

kotlin {
    explicitApi()
    jvmToolchain(17)
    compilerOptions {
        // The module's own wiring is marked for the benefit of other modules; inside it the
        // marker is noise.
        optIn.add("versola.oauth.core.VersolaInternalApi")
    }
}

dependencies {
    // api, not implementation: SessionState is exposed as a Flow (spec/state-machine.md,
    // "Observability"), so the coroutines types are part of this module's ABI. The JVM
    // artifact rather than -android: this module has no Android dispatcher to offer.
    api("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.11.0")

    // Discovery and the token endpoint need an HTTP client and a JSON parser.
    //
    // OkHttp rather than HttpURLConnection: the :okhttp module already pins it, and one HTTP
    // stack across the SDK means one place where timeouts, TLS and proxy behaviour are
    // decided. Same 5.4.0 pin and the same reason for it as :okhttp.
    //
    // kotlinx-serialization rather than org.json: reflection-free, so it survives R8 without
    // keep rules, and available on a plain JVM. api, not implementation: HttpDiscoveryClient
    // takes an OkHttpClient, so the type is on this module's ABI.
    api("com.squareup.okhttp3:okhttp:5.4.0")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.11.0")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.11.0")
    testImplementation("com.squareup.okhttp3:mockwebserver3:5.4.0")
}

apiValidation {
    // Wiring behind the opt-in marker is not public API: keep it out of the dump so that
    // apiCheck holds this module to the surface an app can actually use (architecture
    // review F6).
    nonPublicMarkers.add("versola.oauth.core.VersolaInternalApi")
}
