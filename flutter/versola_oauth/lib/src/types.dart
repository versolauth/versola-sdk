import 'package:flutter/foundation.dart' show listEquals, mapEquals, setEquals;

/// The seven states of `spec/state-machine.md`, and no others.
enum SessionState {
  unauthenticated,
  authorizing,
  authenticated,
  refreshing,
  stepUpRequired,
  locked,
  loggingOut,
}

/// Bearer by default; DPoP when the resource servers verify it (`spec/oauth-sdk-api.md` section 9).
enum TokenBinding { bearer, dpop, dpopRequireHardware }

/// RFC 9126 policy (`spec/oauth-sdk-api.md` section 7).
enum PushedAuthorization { never, whenAdvertised, required }

/// `spec/state-machine.md`'s `locked` state is reachable only under `onAppUnlock`.
enum UnlockPolicy { none, onAppUnlock }

enum Prompt { none, login, consent, selectAccount, create }

/// Explicit endpoints for a provider without discovery (`spec/oauth-sdk-api.md` section 3).
final class ProviderEndpoints {
  const ProviderEndpoints({
    required this.issuer,
    required this.authorizationEndpoint,
    required this.tokenEndpoint,
    required this.jwksUri,
    this.userinfoEndpoint,
    this.revocationEndpoint,
    this.endSessionEndpoint,
    this.pushedAuthorizationRequestEndpoint,
    this.idTokenSigningAlgValuesSupported = const <String>[],
  });
  final String issuer;
  final String authorizationEndpoint;
  final String tokenEndpoint;
  final String jwksUri;
  final String? userinfoEndpoint;
  final String? revocationEndpoint;
  final String? endSessionEndpoint;
  final String? pushedAuthorizationRequestEndpoint;
  final List<String> idTokenSigningAlgValuesSupported;

  @override
  bool operator ==(Object other) =>
      other is ProviderEndpoints &&
      issuer == other.issuer &&
      authorizationEndpoint == other.authorizationEndpoint &&
      tokenEndpoint == other.tokenEndpoint &&
      jwksUri == other.jwksUri &&
      userinfoEndpoint == other.userinfoEndpoint &&
      revocationEndpoint == other.revocationEndpoint &&
      endSessionEndpoint == other.endSessionEndpoint &&
      pushedAuthorizationRequestEndpoint ==
          other.pushedAuthorizationRequestEndpoint &&
      listEquals(
        idTokenSigningAlgValuesSupported,
        other.idTokenSigningAlgValuesSupported,
      );

  @override
  int get hashCode => Object.hash(
    issuer,
    authorizationEndpoint,
    tokenEndpoint,
    jwksUri,
    userinfoEndpoint,
    revocationEndpoint,
    endSessionEndpoint,
    pushedAuthorizationRequestEndpoint,
    Object.hashAll(idTokenSigningAlgValuesSupported),
  );
}

/// The bounds of `spec/retry-policy.md`; a value above a maximum is refused natively.
final class RetryPolicy {
  const RetryPolicy({
    this.maxAttemptsPerOrigin = 3,
    this.maxTotalAttempts = 4,
    this.initialBackoff = const Duration(milliseconds: 500),
    this.backoffMultiplier = 2,
    this.maxBackoff = const Duration(seconds: 8),
    this.totalBudget = const Duration(seconds: 20),
  });
  final int maxAttemptsPerOrigin;
  final int maxTotalAttempts;
  final Duration initialBackoff;
  final double backoffMultiplier;
  final Duration maxBackoff;
  final Duration totalBudget;

  @override
  bool operator ==(Object other) =>
      other is RetryPolicy &&
      maxAttemptsPerOrigin == other.maxAttemptsPerOrigin &&
      maxTotalAttempts == other.maxTotalAttempts &&
      initialBackoff == other.initialBackoff &&
      backoffMultiplier == other.backoffMultiplier &&
      maxBackoff == other.maxBackoff &&
      totalBudget == other.totalBudget;

  @override
  int get hashCode => Object.hash(
    maxAttemptsPerOrigin,
    maxTotalAttempts,
    initialBackoff,
    backoffMultiplier,
    maxBackoff,
    totalBudget,
  );
}

/// What `OAuthClient.create` is given (`spec/oauth-sdk-api.md` section 3). Validated natively,
/// eagerly: a bad value is a `ConfigurationError` from `create`, never behind a login screen.
///
/// Immutable: [scopes] and [protectedOrigins] are copied on construction and exposed
/// unmodifiable, so a set the app keeps changing cannot alter a configuration that was already
/// handed over. Equal by value. Not `const`, because of that copy.
final class OAuthConfiguration {
  OAuthConfiguration({
    this.issuer,
    this.endpoints,
    required this.clientId,
    required this.redirectUri,
    this.postLogoutRedirectUri,
    Set<String> scopes = const <String>{'openid'},
    this.tokenBinding = TokenBinding.bearer,
    this.pushedAuthorization = PushedAuthorization.whenAdvertised,
    Set<String> protectedOrigins = const <String>{},
    this.endSessionEndpoint,
    this.unlockPolicy = UnlockPolicy.none,
    this.clockSkewTolerance = const Duration(seconds: 60),
    this.retryPolicy,
  }) : scopes = Set<String>.unmodifiable(scopes),
       protectedOrigins = Set<String>.unmodifiable(protectedOrigins);
  final String? issuer;
  final ProviderEndpoints? endpoints;
  final String clientId;
  final String redirectUri;
  final String? postLogoutRedirectUri;
  final Set<String> scopes;
  final TokenBinding tokenBinding;
  final PushedAuthorization pushedAuthorization;
  final Set<String> protectedOrigins;
  final String? endSessionEndpoint;
  final UnlockPolicy unlockPolicy;

  /// Whole seconds: a finer value is refused by [OAuthClient.create] with an [ArgumentError]
  /// rather than truncated.
  final Duration clockSkewTolerance;
  final RetryPolicy? retryPolicy;

  @override
  bool operator ==(Object other) =>
      other is OAuthConfiguration &&
      issuer == other.issuer &&
      endpoints == other.endpoints &&
      clientId == other.clientId &&
      redirectUri == other.redirectUri &&
      postLogoutRedirectUri == other.postLogoutRedirectUri &&
      setEquals(scopes, other.scopes) &&
      tokenBinding == other.tokenBinding &&
      pushedAuthorization == other.pushedAuthorization &&
      setEquals(protectedOrigins, other.protectedOrigins) &&
      endSessionEndpoint == other.endSessionEndpoint &&
      unlockPolicy == other.unlockPolicy &&
      clockSkewTolerance == other.clockSkewTolerance &&
      retryPolicy == other.retryPolicy;

  @override
  int get hashCode => Object.hash(
    issuer,
    endpoints,
    clientId,
    redirectUri,
    postLogoutRedirectUri,
    Object.hashAllUnordered(scopes),
    tokenBinding,
    pushedAuthorization,
    Object.hashAllUnordered(protectedOrigins),
    endSessionEndpoint,
    unlockPolicy,
    clockSkewTolerance,
    retryPolicy,
  );
}

/// What one `login()` adds to the configured defaults (`spec/oauth-sdk-api.md` section 6).
///
/// Immutable and equal by value: the collections are copied on construction and exposed
/// unmodifiable. Not `const`, because of that copy.
final class LoginOptions {
  LoginOptions({
    Set<String>? scopes,
    this.prompt,
    this.loginHint,
    List<String> uiLocales = const <String>[],
    List<String> acrValues = const <String>[],
    this.maxAge,
    List<String> resources = const <String>[],
    Map<String, String> extraParameters = const <String, String>{},
    this.ephemeralBrowser = false,
  }) : scopes = scopes == null ? null : Set<String>.unmodifiable(scopes),
       uiLocales = List<String>.unmodifiable(uiLocales),
       acrValues = List<String>.unmodifiable(acrValues),
       resources = List<String>.unmodifiable(resources),
       extraParameters = Map<String, String>.unmodifiable(extraParameters);
  final Set<String>? scopes;
  final Prompt? prompt;
  final String? loginHint;
  final List<String> uiLocales;
  final List<String> acrValues;
  final int? maxAge;
  final List<String> resources;
  final Map<String, String> extraParameters;
  final bool ephemeralBrowser;

  @override
  bool operator ==(Object other) =>
      other is LoginOptions &&
      (scopes == null
          ? other.scopes == null
          : other.scopes != null && setEquals(scopes, other.scopes)) &&
      prompt == other.prompt &&
      loginHint == other.loginHint &&
      listEquals(uiLocales, other.uiLocales) &&
      listEquals(acrValues, other.acrValues) &&
      maxAge == other.maxAge &&
      listEquals(resources, other.resources) &&
      mapEquals(extraParameters, other.extraParameters) &&
      ephemeralBrowser == other.ephemeralBrowser;

  @override
  int get hashCode => Object.hash(
    scopes == null ? null : Object.hashAllUnordered(scopes!),
    prompt,
    loginHint,
    Object.hashAll(uiLocales),
    Object.hashAll(acrValues),
    maxAge,
    Object.hashAll(resources),
    Object.hashAllUnordered(
      extraParameters.entries.map((e) => Object.hash(e.key, e.value)),
    ),
    ephemeralBrowser,
  );
}

/// What `logout()` does beyond the unconditional local wipe (`spec/oauth-sdk-api.md` section 12).
final class LogoutOptions {
  const LogoutOptions({this.endSession = true, this.revoke = true});
  final bool endSession;
  final bool revoke;

  @override
  bool operator ==(Object other) =>
      other is LogoutOptions &&
      endSession == other.endSession &&
      revoke == other.revoke;

  @override
  int get hashCode => Object.hash(endSession, revoke);
}

/// The short-lived access token, the one credential that crosses the bridge (issue #46
/// decision 7). Its `toString` redacts the value.
final class AccessToken {
  const AccessToken({required this.value, required this.tokenType});
  final String value;
  final String tokenType;
  @override
  bool operator ==(Object other) =>
      other is AccessToken &&
      value == other.value &&
      tokenType == other.tokenType;

  @override
  int get hashCode => Object.hash(value, tokenType);

  @override
  String toString() => 'AccessToken($tokenType, redacted)';
}

/// The claims of the validated ID token of this session (`spec/oauth-sdk-api.md` section 11).
final class IdTokenClaims {
  const IdTokenClaims({
    required this.subject,
    required this.issuer,
    required this.audience,
    required this.issuedAt,
    required this.expiresAt,
    this.authTime,
    this.acr,
    this.amr = const <String>[],
    this.authorizedParty,
    this.all = const <String, String>{},
  });
  final String subject;
  final String issuer;
  final List<String> audience;
  final DateTime issuedAt;
  final DateTime expiresAt;
  final DateTime? authTime;
  final String? acr;
  final List<String> amr;
  final String? authorizedParty;

  /// Every claim but `nonce`, as text; the same map the native SDKs expose.
  final Map<String, String> all;
  @override
  bool operator ==(Object other) =>
      other is IdTokenClaims &&
      subject == other.subject &&
      issuer == other.issuer &&
      listEquals(audience, other.audience) &&
      issuedAt == other.issuedAt &&
      expiresAt == other.expiresAt &&
      authTime == other.authTime &&
      acr == other.acr &&
      listEquals(amr, other.amr) &&
      authorizedParty == other.authorizedParty &&
      mapEquals(all, other.all);

  @override
  int get hashCode => Object.hash(
    subject,
    issuer,
    Object.hashAll(audience),
    issuedAt,
    expiresAt,
    authTime,
    acr,
    Object.hashAll(amr),
    authorizedParty,
    Object.hashAllUnordered(
      all.entries.map((e) => Object.hash(e.key, e.value)),
    ),
  );

  @override
  String toString() => 'IdTokenClaims(issuer: $issuer, subject: redacted)';
}

/// The UserInfo response (OpenID Connect Core 5.3). Profile data is personal data: redacted.
final class UserInfo {
  const UserInfo({required this.subject, required this.claims});
  final String subject;
  final Map<String, String> claims;
  @override
  bool operator ==(Object other) =>
      other is UserInfo &&
      subject == other.subject &&
      mapEquals(claims, other.claims);

  @override
  int get hashCode => Object.hash(
    subject,
    Object.hashAllUnordered(
      claims.entries.map((e) => Object.hash(e.key, e.value)),
    ),
  );

  @override
  String toString() => 'UserInfo(redacted)';
}

/// What `logout()` did beyond the unconditional local wipe.
final class LogoutOutcome {
  const LogoutOutcome({required this.sessionEnded, required this.tokenRevoked});
  final bool sessionEnded;
  final bool tokenRevoked;

  @override
  bool operator ==(Object other) =>
      other is LogoutOutcome &&
      sessionEnded == other.sessionEnded &&
      tokenRevoked == other.tokenRevoked;

  @override
  int get hashCode => Object.hash(sessionEnded, tokenRevoked);
}
