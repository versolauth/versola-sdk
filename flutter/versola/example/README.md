# versola example

Creates the client, shows the session state, and has sign-in and sign-out buttons. The
configuration is `example.com` placeholders; point it at a deployment with `--dart-define`:

```bash
fvm flutter run --dart-define=EDGE_URL=https://id.example.com --dart-define=CLIENT_ID=example-app \
  --dart-define=REDIRECT_URI=https://app.example.com/oauth
```

On Android the redirect URI must match the App Link declared in
`android/app/src/main/AndroidManifest.xml` (the `VersolaRedirectActivity` entry); on iOS it must be a
Universal Link of the app (`ASWebAuthenticationSession` intercepts the https callback on iOS 17.4
and newer).

The Android build resolves `io.versola:versola-android` from this checkout (a composite build in
`android/settings.gradle.kts` substitutes the repository's `:sdk` project), because that artefact
is not published yet.
