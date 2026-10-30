/// The Versola generic OAuth 2.0 / OpenID Connect SDK for Flutter: a binding over the native
/// Android and iOS SDKs of `versolauth/versola-sdk` (`spec/oauth-sdk-api.md`).
///
/// Nothing here implements the protocol. Dart holds the API shape, the mapping to the typed
/// error hierarchy and the client handle; the authorization request, PKCE, token exchange,
/// refresh, ID-token validation, DPoP and storage are the native SDKs' and stay there. The
/// generated bridge (`src/messages.g.dart`) is not exported.
library;

export 'src/client.dart' show OAuthClient;
export 'src/errors.dart';
export 'src/types.dart';
