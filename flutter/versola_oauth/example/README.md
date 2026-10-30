# versola_oauth example

Sign-in, refresh, access token, UserInfo and sign-out over the binding, with the session state
and the error category of every call on screen. The configuration is `example.com` placeholders;
point it at a provider with `--dart-define`:

```bash
fvm flutter run --dart-define=ISSUER=https://id.example.com --dart-define=CLIENT_ID=example-app \
  --dart-define=REDIRECT_URI=https://app.example.com/oauth
```

On Android the redirect URI must match the App Link declared in
`android/app/src/main/AndroidManifest.xml`; on iOS it must be a Universal Link of the app
(`ASWebAuthenticationSession` intercepts the https callback on iOS 17.4 and newer).
