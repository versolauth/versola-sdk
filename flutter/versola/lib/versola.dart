/// The Versola facade for Flutter: a binding over the native `Versola` SDKs of Android and iOS
/// (`spec/versola-sdk-api.md` in `versolauth/versola-sdk`), which sign a native app in to a Versola
/// deployment through its edge, with a DPoP key that never leaves the device.
///
/// Nothing here implements the protocol. Dart holds the API shape, the mapping to the typed error
/// hierarchy and the client handle; the authorization request, the token calls, ID-token checks,
/// DPoP and storage are the native SDKs' and stay there. Nothing credential-shaped crosses the
/// bridge, the access token included: apps call their API through [Versola.httpClient], which
/// executes the request natively. The generated bridge (`src/messages.g.dart`) is not exported.
///
/// The types the two facades share are `package:versola_oauth`'s and are re-exported here, not
/// copied. An app that imports both packages has two `LoginOptions`; hide one.
library;

// Exactly the shared types this API uses; never a blanket export, so a type of the generic
// facade that this one does not have (AccessToken, UserInfo, OAuthConfiguration) stays out.
export 'package:versola_oauth/versola_oauth.dart'
    show
        ConfigurationDetail,
        ConfigurationError,
        IdTokenClaims,
        IdTokenRejection,
        LogoutOptions,
        LogoutOutcome,
        OAuthError,
        Prompt,
        ReauthenticateError,
        ReauthenticateReason,
        RecoverableCause,
        RecoverableError,
        RetryPolicy,
        SessionState,
        StepUpError,
        UnlockPolicy;

export 'src/api.dart' show VersolaApi;
export 'src/client.dart' show Versola;
export 'src/configuration.dart' show LoginOptions, VersolaConfiguration;
