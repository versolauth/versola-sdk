import 'package:flutter/foundation.dart' show listEquals, setEquals;
import 'package:versola_oauth/versola_oauth.dart'
    show Prompt, RetryPolicy, UnlockPolicy;

/// What `Versola.create` is given (`spec/versola-sdk-api.md` section 3). Validated natively,
/// eagerly: a bad value is a `ConfigurationError` from `create`, never behind a login screen.
///
/// There is nothing to choose about the protocol: an edge-fronted native client is always
/// DPoP-bound, always pushes its request and always redirects to an `https` link, so none of
/// those is a parameter. Immutable and equal by value.
final class VersolaConfiguration {
  const VersolaConfiguration({
    required this.edgeUrl,
    required this.clientId,
    required this.redirectUri,
    this.issuer,
    this.postLogoutRedirectUri,
    this.requireHardwareKey = false,
    this.unlockPolicy = UnlockPolicy.none,
    this.retryPolicy,
    this.clockSkewTolerance = const Duration(seconds: 60),
  });

  /// The public origin of the edge: `https`, or `http` on a loopback host. An origin and nothing
  /// more (no path, query or fragment).
  final String edgeUrl;
  final String clientId;

  /// An `https` App Link (Android) or Universal Link (iOS) of the app.
  final String redirectUri;

  /// The issuer of the deployment, compared as written with the redirect's `iss` and the ID
  /// token's. Null: the native side uses [edgeUrl], which is what it is for a deployment's own
  /// edge. Set it for a partner's edge, or when the issuer is written with a trailing slash.
  final String? issuer;

  /// An `https` link like [redirectUri]; without it `logout` reports `sessionEnded == false`.
  final String? postLogoutRedirectUri;

  /// Refuse to sign in with a DPoP key that did not land in hardware.
  final bool requireHardwareKey;
  final UnlockPolicy unlockPolicy;

  /// Null: the native default policy.
  final RetryPolicy? retryPolicy;

  /// Whole seconds, at most five minutes (checked natively): a finer value is refused by
  /// `Versola.create` with an [ArgumentError] rather than truncated.
  final Duration clockSkewTolerance;

  @override
  bool operator ==(Object other) =>
      other is VersolaConfiguration &&
      edgeUrl == other.edgeUrl &&
      clientId == other.clientId &&
      redirectUri == other.redirectUri &&
      issuer == other.issuer &&
      postLogoutRedirectUri == other.postLogoutRedirectUri &&
      requireHardwareKey == other.requireHardwareKey &&
      unlockPolicy == other.unlockPolicy &&
      retryPolicy == other.retryPolicy &&
      clockSkewTolerance == other.clockSkewTolerance;

  @override
  int get hashCode => Object.hash(
    edgeUrl,
    clientId,
    redirectUri,
    issuer,
    postLogoutRedirectUri,
    requireHardwareKey,
    unlockPolicy,
    retryPolicy,
    clockSkewTolerance,
  );
}

/// What one `login()` asks for (`spec/versola-sdk-api.md` section 5). Each option is one of the
/// authorization parameters edge forwards from `/native/start`, and there is no other: edge drops
/// a parameter it does not forward without an error, so a free-form map here would let an app set
/// something that silently does nothing.
///
/// Immutable and equal by value: the collections are copied on construction and exposed
/// unmodifiable. Not `const`, because of that copy.
final class LoginOptions {
  LoginOptions({
    Set<String> scopes = const <String>{},
    List<String> acrValues = const <String>[],
    this.maxAge,
    this.prompt,
    this.loginHint,
    List<String> uiLocales = const <String>[],
    List<String> resources = const <String>[],
    this.claims,
    this.authorizationDetails,
    this.ephemeralBrowser = false,
  }) : scopes = Set<String>.unmodifiable(scopes),
       acrValues = List<String>.unmodifiable(acrValues),
       uiLocales = List<String>.unmodifiable(uiLocales),
       resources = List<String>.unmodifiable(resources);

  /// Added to `openid` and `offline_access`, which every sign-in asks for.
  final Set<String> scopes;

  /// The authentication contexts to ask for. A step-up takes them from the challenge.
  final List<String> acrValues;

  /// Seconds since the user last authenticated; when set, the ID token's `auth_time` is checked.
  final int? maxAge;

  /// `Prompt.none` makes an interaction error `ReauthenticateError(interactionRequired)`.
  final Prompt? prompt;
  final String? loginHint;

  /// `ui_locales`, in order of preference.
  final List<String> uiLocales;

  /// RFC 8707 `resource`, one per value; sent at `/native/start` only.
  final List<String> resources;

  /// OpenID Connect Core 5.5 `claims`: a JSON object as text, sent as given.
  final String? claims;

  /// RFC 9396 `authorization_details`: a JSON array as text, sent as given.
  final String? authorizationDetails;

  /// Open the browser without the user's shared browsing state. Off by default: it breaks
  /// passkeys and single sign-on.
  final bool ephemeralBrowser;

  @override
  bool operator ==(Object other) =>
      other is LoginOptions &&
      setEquals(scopes, other.scopes) &&
      listEquals(acrValues, other.acrValues) &&
      maxAge == other.maxAge &&
      prompt == other.prompt &&
      loginHint == other.loginHint &&
      listEquals(uiLocales, other.uiLocales) &&
      listEquals(resources, other.resources) &&
      claims == other.claims &&
      authorizationDetails == other.authorizationDetails &&
      ephemeralBrowser == other.ephemeralBrowser;

  @override
  int get hashCode => Object.hash(
    Object.hashAllUnordered(scopes),
    Object.hashAll(acrValues),
    maxAge,
    prompt,
    loginHint,
    Object.hashAll(uiLocales),
    Object.hashAll(resources),
    claims,
    authorizationDetails,
    ephemeralBrowser,
  );
}
