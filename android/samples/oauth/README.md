# Versola OAuth sample

A minimal Android app over the generic facade `OAuthClient` (module `:oauth`): sign in, call a
protected resource, sign out. Its purpose is its build, not its screen.

## What it proves

- The release variant is built with `isMinifyEnabled = true` (R8, `proguard-android-optimize.txt`)
  and an intentionally empty `proguard-rules.pro`. If that build passes, the SDK needs no consumer
  keep rules (architecture review F9).
- The instrumented `SmokeTest` runs discovery, sign-in, an authenticated call, userinfo and
  sign-out against a provider on a MockWebServer, with the real Android Keystore wrapping the
  credentials. Only the browser leg is replaced, since a test cannot drive an Auth Tab. It runs
  on the debug build: AGP builds a test APK without what the app's graph already has, and R8
  strips the unused parts of that from a minified app (androidx.tracing, parts of the Kotlin
  stdlib), so the test only starts on a minified build once the app keeps them, which is the
  keep rule this module exists to show is not needed. The R8 proof is the release build; the
  device proof is the smoke test.

Nothing here is published, and the release APK is built unsigned.

## Build the minified APK

```bash
cd android && ./gradlew :samples:oauth:assembleRelease
```

The APK is under `android/samples/oauth/build/outputs/apk/release/`. A missing-class warning or
error from R8 is a bug in the SDK to fix there; do not paper over it with rules in this module.

## Run the smoke test

Needs a booted emulator or a device (API 26 or newer):

```bash
cd android && ./gradlew :samples:oauth:connectedDebugAndroidTest
```

The debug build allows cleartext traffic, because the MockWebServer listens on loopback over
http. The release build does not.

## Point it at a real provider

The configuration is read from Gradle properties at build time and baked into `BuildConfig`.
The defaults are placeholders on example.com:

| Property                      | Default                              |
| ----------------------------- | ------------------------------------ |
| `sampleIssuer`                | `https://id.example.com`             |
| `sampleClientId`              | `sample-app`                         |
| `sampleRedirectUri`           | `https://app.example.com/oauth`      |
| `samplePostLogoutRedirectUri` | `https://app.example.com/signed-out` |
| `sampleResourceUrl`           | `https://api.example.com/me`         |

```bash
cd android && ./gradlew :samples:oauth:assembleRelease \
  -PsampleIssuer=https://id.example.com -PsampleClientId=my-client \
  -PsampleRedirectUri=https://app.example.com/oauth \
  -PsampleResourceUrl=https://api.example.com/me
```

The redirect URI must be registered with the provider, and the host and path in
`src/main/AndroidManifest.xml` (the `VersolaRedirectActivity` intent filter) must match it. That
host has to be your app's own verified App Link: serve `/.well-known/assetlinks.json` for the
app's package and signing certificate on it. A host you do not control cannot be verified, and the
browser will not hand the redirect to the app.
