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
}

/// What `OAuthClient.create` is given (`spec/oauth-sdk-api.md` section 3). Validated natively,
/// eagerly: a bad value is a `ConfigurationError` from `create`, never behind a login screen.
final class OAuthConfiguration {
  const OAuthConfiguration({
    this.issuer,
    this.endpoints,
    required this.clientId,
    required this.redirectUri,
    this.postLogoutRedirectUri,
    this.scopes = const <String>{'openid'},
    this.tokenBinding = TokenBinding.bearer,
    this.pushedAuthorization = PushedAuthorization.whenAdvertised,
    this.protectedOrigins = const <String>{},
    this.endSessionEndpoint,
    this.unlockPolicy = UnlockPolicy.none,
    this.clockSkewTolerance = const Duration(seconds: 60),
    this.retryPolicy,
  });
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
  final Duration clockSkewTolerance;
  final RetryPolicy? retryPolicy;
}

/// What one `login()` adds to the configured defaults (`spec/oauth-sdk-api.md` section 6).
final class LoginOptions {
  const LoginOptions({
    this.scopes,
    this.prompt,
    this.loginHint,
    this.uiLocales = const <String>[],
    this.acrValues = const <String>[],
    this.maxAge,
    this.resources = const <String>[],
    this.extraParameters = const <String, String>{},
    this.ephemeralBrowser = false,
  });
  final Set<String>? scopes;
  final Prompt? prompt;
  final String? loginHint;
  final List<String> uiLocales;
  final List<String> acrValues;
  final int? maxAge;
  final List<String> resources;
  final Map<String, String> extraParameters;
  final bool ephemeralBrowser;
}

/// What `logout()` does beyond the unconditional local wipe (`spec/oauth-sdk-api.md` section 12).
final class LogoutOptions {
  const LogoutOptions({this.endSession = true, this.revoke = true});
  final bool endSession;
  final bool revoke;
}

/// The short-lived access token, the one credential that crosses the bridge (issue #46
/// decision 7). Its `toString` redacts the value.
final class AccessToken {
  const AccessToken({required this.value, required this.tokenType});
  final String value;
  final String tokenType;
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
  String toString() => 'IdTokenClaims(issuer: $issuer, subject: redacted)';
}

/// The UserInfo response (OpenID Connect Core 5.3). Profile data is personal data: redacted.
final class UserInfo {
  const UserInfo({required this.subject, required this.claims});
  final String subject;
  final Map<String, String> claims;
  @override
  String toString() => 'UserInfo(redacted)';
}

/// What `logout()` did beyond the unconditional local wipe.
final class LogoutOutcome {
  const LogoutOutcome({required this.sessionEnded, required this.tokenRevoked});
  final bool sessionEnded;
  final bool tokenRevoked;
}
