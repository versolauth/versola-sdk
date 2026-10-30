// The Pigeon contract between Dart and the native facades (`.claude/rules/flutter.md`): data
// shapes and typed results only. No protocol logic lives on either side of this file; the
// native half calls the public API of `OAuthClient` on Android and `VersolaOAuth` on iOS.
//
// Regenerate with `dart run pigeon --input pigeons/messages.dart` (see pubspec.yaml); the
// generated files are never hand-edited.
import 'package:pigeon/pigeon.dart';

@ConfigurePigeon(
  PigeonOptions(
    dartOut: 'lib/src/messages.g.dart',
    dartOptions: DartOptions(),
    kotlinOut: 'android/src/main/kotlin/versola/oauth/flutter/Messages.g.kt',
    kotlinOptions: KotlinOptions(package: 'versola.oauth.flutter'),
    swiftOut: 'ios/versola_oauth/Sources/versola_oauth/Messages.g.swift',
    swiftOptions: SwiftOptions(),
    dartPackageName: 'versola_oauth',
  ),
)
/// The seven states of `spec/state-machine.md`, and no others.
enum SessionStateMessage {
  unauthenticated,
  authorizing,
  authenticated,
  refreshing,
  stepUpRequired,
  locked,
  loggingOut,
}

enum TokenBindingMessage { bearer, dpop, dpopRequireHardware }

enum PushedAuthorizationMessage { never, whenAdvertised, required }

enum UnlockPolicyMessage { none, onAppUnlock }

enum PromptMessage { none, login, consent, selectAccount, create }

/// The four categories of `spec/errors.md`; the category is the contract.
enum ErrorCategoryMessage { recoverable, reauthenticate, stepUp, configuration }

/// Explicit endpoints for a provider without discovery (`spec/oauth-sdk-api.md` section 3).
class EndpointsMessage {
  EndpointsMessage({
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
  String issuer;
  String authorizationEndpoint;
  String tokenEndpoint;
  String jwksUri;
  String? userinfoEndpoint;
  String? revocationEndpoint;
  String? endSessionEndpoint;
  String? pushedAuthorizationRequestEndpoint;
  List<String> idTokenSigningAlgValuesSupported;
}

class RetryPolicyMessage {
  RetryPolicyMessage({
    required this.maxAttemptsPerOrigin,
    required this.maxTotalAttempts,
    required this.initialBackoffMillis,
    required this.backoffMultiplier,
    required this.maxBackoffMillis,
    required this.totalBudgetMillis,
  });
  int maxAttemptsPerOrigin;
  int maxTotalAttempts;
  int initialBackoffMillis;
  double backoffMultiplier;
  int maxBackoffMillis;
  int totalBudgetMillis;
}

/// `spec/oauth-sdk-api.md` section 3, as the native configuration type reads it.
class ConfigurationMessage {
  ConfigurationMessage({
    this.issuer,
    this.endpoints,
    required this.clientId,
    required this.redirectUri,
    this.postLogoutRedirectUri,
    required this.scopes,
    required this.tokenBinding,
    required this.pushedAuthorization,
    required this.protectedOrigins,
    this.endSessionEndpoint,
    required this.unlockPolicy,
    required this.clockSkewToleranceSeconds,
    this.retryPolicy,
  });
  String? issuer;
  EndpointsMessage? endpoints;
  String clientId;
  String redirectUri;
  String? postLogoutRedirectUri;
  List<String> scopes;
  TokenBindingMessage tokenBinding;
  PushedAuthorizationMessage pushedAuthorization;
  List<String> protectedOrigins;
  String? endSessionEndpoint;
  UnlockPolicyMessage unlockPolicy;
  int clockSkewToleranceSeconds;
  RetryPolicyMessage? retryPolicy;
}

class LoginOptionsMessage {
  LoginOptionsMessage({
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
  List<String>? scopes;
  PromptMessage? prompt;
  String? loginHint;
  List<String> uiLocales;
  List<String> acrValues;
  int? maxAge;
  List<String> resources;
  Map<String, String> extraParameters;
  bool ephemeralBrowser;
}

class LogoutOptionsMessage {
  LogoutOptionsMessage({this.endSession = true, this.revoke = true});
  bool endSession;
  bool revoke;
}

/// One error of the taxonomy, flattened for the wire. `kind` is the case name of the native
/// error (`userCancelled`, `grantRejected`, `idTokenRejected`, …) so Dart rebuilds the same
/// sealed hierarchy; the optional fields are that case's payload. Nothing credential-shaped
/// is ever in `detail` or `description` (the native errors already guarantee that).
class ErrorMessage {
  ErrorMessage({
    required this.category,
    required this.kind,
    required this.message,
    this.code,
    this.errorDescription,
    this.detail,
    this.acrValues,
    this.maxAge,
    this.attempts,
    this.elapsedMillis,
    this.status,
    this.retryAfterMillis,
    this.origin,
    this.expected,
    this.received,
    this.field,
    this.capability,
    this.idTokenRejection,
  });
  ErrorCategoryMessage category;
  String kind;
  String message;
  String? code;

  /// `error_description`; not `description`, a name Swift's NSObject reserves.
  String? errorDescription;
  String? detail;
  List<String>? acrValues;
  int? maxAge;
  int? attempts;
  int? elapsedMillis;

  /// The HTTP status of a `server` cause, and its parsed `Retry-After` in milliseconds.
  int? status;
  int? retryAfterMillis;
  String? origin;
  String? expected;
  String? received;
  String? field;
  String? capability;
  String? idTokenRejection;
}

class AccessTokenMessage {
  AccessTokenMessage({required this.value, required this.tokenType});
  String value;
  String tokenType;
}

class IdTokenClaimsMessage {
  IdTokenClaimsMessage({
    required this.subject,
    required this.issuer,
    required this.audience,
    required this.issuedAtEpochSeconds,
    required this.expiresAtEpochSeconds,
    this.authTimeEpochSeconds,
    this.acr,
    required this.amr,
    this.authorizedParty,
    required this.all,
  });
  String subject;
  String issuer;
  List<String> audience;
  int issuedAtEpochSeconds;
  int expiresAtEpochSeconds;
  int? authTimeEpochSeconds;
  String? acr;
  List<String> amr;
  String? authorizedParty;
  Map<String, String> all;
}

class UserInfoMessage {
  UserInfoMessage({required this.subject, required this.claims});
  String subject;
  Map<String, String> claims;
}

class LogoutOutcomeMessage {
  LogoutOutcomeMessage({
    required this.sessionEnded,
    required this.tokenRevoked,
  });
  bool sessionEnded;
  bool tokenRevoked;
}

/// Result-shaped answers (`flutter.md`, Bridge): every method answers with its value or with
/// the typed error, never with a thrown `PlatformException` that would collapse the category.
/// Native code catches everything: a `VersolaError` / `OAuthError` crosses as itself, any other
/// exception as a `Configuration` naming only its class.
sealed class VoidResult {}

class VoidOk extends VoidResult {
  VoidOk();
}

class VoidFailure extends VoidResult {
  VoidFailure({required this.error});
  ErrorMessage error;
}

/// `create` answers with the handle native chose for this client; every later call and the
/// event channel's instance name use it, so Dart never derives an identity of its own.
sealed class CreateResult {}

class CreateOk extends CreateResult {
  CreateOk({required this.handle});
  String handle;
}

class CreateFailure extends CreateResult {
  CreateFailure({required this.error});
  ErrorMessage error;
}

sealed class SessionStateResult {}

class SessionStateOk extends SessionStateResult {
  SessionStateOk({required this.state});
  SessionStateMessage state;
}

class SessionStateFailure extends SessionStateResult {
  SessionStateFailure({required this.error});
  ErrorMessage error;
}

sealed class AccessTokenResult {}

class AccessTokenOk extends AccessTokenResult {
  AccessTokenOk({required this.token});
  AccessTokenMessage token;
}

class AccessTokenFailure extends AccessTokenResult {
  AccessTokenFailure({required this.error});
  ErrorMessage error;
}

sealed class ClaimsResult {}

class ClaimsOk extends ClaimsResult {
  ClaimsOk({this.claims});
  IdTokenClaimsMessage? claims;
}

class ClaimsFailure extends ClaimsResult {
  ClaimsFailure({required this.error});
  ErrorMessage error;
}

sealed class UserInfoResult {}

class UserInfoOk extends UserInfoResult {
  UserInfoOk({required this.userInfo});
  UserInfoMessage userInfo;
}

class UserInfoFailure extends UserInfoResult {
  UserInfoFailure({required this.error});
  ErrorMessage error;
}

sealed class LogoutResult {}

class LogoutOk extends LogoutResult {
  LogoutOk({required this.outcome});
  LogoutOutcomeMessage outcome;
}

class LogoutFailure extends LogoutResult {
  LogoutFailure({required this.error});
  ErrorMessage error;
}

sealed class KeyAttestationResult {}

/// `secureEnclave`, `strongBox`, `trustedEnvironment`, `software`, or null under bearer.
class KeyAttestationOk extends KeyAttestationResult {
  KeyAttestationOk({this.tier});
  String? tier;
}

class KeyAttestationFailure extends KeyAttestationResult {
  KeyAttestationFailure({required this.error});
  ErrorMessage error;
}

/// Dart → native. Every method but `create` takes the `handle` `create` returned: one native
/// client per configuration per process, as the native facades promise.
@HostApi()
abstract class OAuthHostApi {
  /// Validates the configuration and wires (or finds) the native client, and answers with the
  /// handle that names it from now on. The same configuration answers the same handle.
  @async
  CreateResult create(ConfigurationMessage configuration);

  @async
  SessionStateResult sessionState(String handle);

  @async
  VoidResult login(String handle, LoginOptionsMessage options);

  @async
  VoidResult stepUp(
    String handle,
    List<String> acrValues,
    int? maxAge,
    LoginOptionsMessage options,
  );

  @async
  LogoutResult logout(String handle, LogoutOptionsMessage options);

  /// The short-lived access token, the one credential that crosses (issue #46 decision 7).
  @async
  AccessTokenResult accessToken(String handle);

  @async
  VoidResult refresh(String handle);

  @async
  ClaimsResult claims(String handle);

  @async
  UserInfoResult userInfo(String handle);

  @async
  KeyAttestationResult keyAttestation(String handle);
}

/// Native → Dart: the state machine, fed by the native `Flow` / `AsyncStream`; the native
/// collection ends when the subscription does. One channel per client: the handle `create`
/// returned is the Pigeon `instanceName`. The generated stream must be subscribed once per
/// client (a second `EventChannel` of the same name replaces the first's handler); the Dart
/// client shares one subscription among its listeners.
@EventChannelApi()
abstract class SessionStateEvents {
  SessionStateMessage sessionStates();
}
