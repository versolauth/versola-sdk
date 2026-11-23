// The Pigeon contract between Dart and the native `Versola` facades (`.claude/rules/flutter.md`):
// data shapes and typed results only. No protocol logic lives on either side of this file; the
// native half calls the public API of `versola.sdk.Versola` on Android and `VersolaSDK.Versola`
// on iOS (`spec/versola-sdk-api.md`).
//
// Every name is prefixed `Versola` and the Dart package name differs from `versola_oauth`'s, so
// the generated channel names (`dev.flutter.pigeon.versola.VersolaHostApi.*`) and the generated
// Kotlin and Swift types cannot collide with the generic plugin's when an app has both.
//
// Nothing credential-shaped is declared here, the access token included: the Versola facade has
// no `accessToken()` (`spec/versola-sdk-api.md` section 10) and no message below could carry one.
//
// Regenerate with `dart run pigeon --input pigeons/messages.dart` (see pubspec.yaml); the
// generated files are never hand-edited.
import 'package:pigeon/pigeon.dart';

@ConfigurePigeon(
  PigeonOptions(
    dartOut: 'lib/src/messages.g.dart',
    dartOptions: DartOptions(),
    kotlinOut: 'android/src/main/kotlin/versola/sdk/flutter/Messages.g.kt',
    kotlinOptions: KotlinOptions(package: 'versola.sdk.flutter'),
    swiftOut: 'ios/versola/Sources/versola/Messages.g.swift',
    swiftOptions: SwiftOptions(),
    dartPackageName: 'versola',
  ),
)
/// The seven states of `spec/state-machine.md`, and no others.
enum VersolaSessionStateMessage {
  unauthenticated,
  authorizing,
  authenticated,
  refreshing,
  stepUpRequired,
  locked,
  loggingOut,
}

enum VersolaUnlockPolicyMessage { none, onAppUnlock }

enum VersolaPromptMessage { none, login, consent, selectAccount, create }

/// The four categories of `spec/errors.md`; the category is the contract.
enum VersolaErrorCategoryMessage {
  recoverable,
  reauthenticate,
  stepUp,
  configuration,
}

class VersolaRetryPolicyMessage {
  VersolaRetryPolicyMessage({
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

/// `spec/versola-sdk-api.md` section 3, as the native configuration types read it. `issuer` is
/// null when the app did not set one: the native side then defaults it to `edgeUrl`.
class VersolaConfigurationMessage {
  VersolaConfigurationMessage({
    required this.edgeUrl,
    required this.clientId,
    required this.redirectUri,
    this.issuer,
    this.postLogoutRedirectUri,
    required this.requireHardwareKey,
    required this.unlockPolicy,
    required this.clockSkewToleranceSeconds,
    this.retryPolicy,
  });
  String edgeUrl;
  String clientId;
  String redirectUri;
  String? issuer;
  String? postLogoutRedirectUri;
  bool requireHardwareKey;
  VersolaUnlockPolicyMessage unlockPolicy;
  int clockSkewToleranceSeconds;
  VersolaRetryPolicyMessage? retryPolicy;
}

/// `spec/versola-sdk-api.md` section 5. `claims` and `authorizationDetails` are JSON as text and
/// cross untouched. There is no parameter map: the native options have none.
class VersolaLoginOptionsMessage {
  VersolaLoginOptionsMessage({
    this.scopes = const <String>[],
    this.acrValues = const <String>[],
    this.maxAge,
    this.prompt,
    this.loginHint,
    this.uiLocales = const <String>[],
    this.resources = const <String>[],
    this.claims,
    this.authorizationDetails,
    this.ephemeralBrowser = false,
  });
  List<String> scopes;
  List<String> acrValues;
  int? maxAge;
  VersolaPromptMessage? prompt;
  String? loginHint;
  List<String> uiLocales;
  List<String> resources;
  String? claims;
  String? authorizationDetails;
  bool ephemeralBrowser;
}

class VersolaLogoutOptionsMessage {
  VersolaLogoutOptionsMessage({this.endSession = true, this.revoke = true});
  bool endSession;
  bool revoke;
}

/// One error of the taxonomy, flattened for the wire. `kind` is the case name of the native
/// error (`userCancelled`, `grantRejected`, `idTokenRejected`, `accountMismatch`, …) so Dart
/// rebuilds the same sealed hierarchy; the optional fields are that case's payload. A case Dart
/// has no name for crosses with `kind: 'unknown'` and its name in `detail`, never as a guessed
/// real case; that is how the Versola facade's `edge_client_unknown` arrives (its stable code in
/// `sdkCode`). Nothing credential-shaped is ever in `detail` or `errorDescription` (the native
/// errors already guarantee that).
class VersolaErrorMessage {
  VersolaErrorMessage({
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
    this.sdkCode,
  });
  VersolaErrorCategoryMessage category;
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

  /// The native error's stable `code` (`spec/errors.md`, "Stable codes"), e.g.
  /// `configuration.edge_client_unknown`. Not [code], which is the provider's OAuth error code.
  String? sdkCode;
}

class VersolaIdTokenClaimsMessage {
  VersolaIdTokenClaimsMessage({
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

class VersolaLogoutOutcomeMessage {
  VersolaLogoutOutcomeMessage({
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
sealed class VersolaVoidResult {}

class VersolaVoidOk extends VersolaVoidResult {
  VersolaVoidOk();
}

class VersolaVoidFailure extends VersolaVoidResult {
  VersolaVoidFailure({required this.error});
  VersolaErrorMessage error;
}

/// `create` answers with the handle native chose for this client; every later call and the
/// event channel's instance name use it, so Dart never derives an identity of its own.
sealed class VersolaCreateResult {}

class VersolaCreateOk extends VersolaCreateResult {
  VersolaCreateOk({required this.handle});
  String handle;
}

class VersolaCreateFailure extends VersolaCreateResult {
  VersolaCreateFailure({required this.error});
  VersolaErrorMessage error;
}

sealed class VersolaSessionStateResult {}

class VersolaSessionStateOk extends VersolaSessionStateResult {
  VersolaSessionStateOk({required this.state});
  VersolaSessionStateMessage state;
}

class VersolaSessionStateFailure extends VersolaSessionStateResult {
  VersolaSessionStateFailure({required this.error});
  VersolaErrorMessage error;
}

sealed class VersolaClaimsResult {}

class VersolaClaimsOk extends VersolaClaimsResult {
  VersolaClaimsOk({this.claims});
  VersolaIdTokenClaimsMessage? claims;
}

class VersolaClaimsFailure extends VersolaClaimsResult {
  VersolaClaimsFailure({required this.error});
  VersolaErrorMessage error;
}

sealed class VersolaLogoutResult {}

class VersolaLogoutOk extends VersolaLogoutResult {
  VersolaLogoutOk({required this.outcome});
  VersolaLogoutOutcomeMessage outcome;
}

class VersolaLogoutFailure extends VersolaLogoutResult {
  VersolaLogoutFailure({required this.error});
  VersolaErrorMessage error;
}

sealed class VersolaKeyAttestationResult {}

/// `secureEnclave`, `strongBox`, `trustedEnvironment`, `software`, or null.
class VersolaKeyAttestationOk extends VersolaKeyAttestationResult {
  VersolaKeyAttestationOk({this.tier});
  String? tier;
}

class VersolaKeyAttestationFailure extends VersolaKeyAttestationResult {
  VersolaKeyAttestationFailure({required this.error});
  VersolaErrorMessage error;
}

/// One header line, name and value as they are on the wire. A list of these rather than a map:
/// a name that appears twice (`WWW-Authenticate`, `Set-Cookie`) keeps both values and their order
/// across the bridge.
class VersolaHttpHeaderMessage {
  VersolaHttpHeaderMessage({required this.name, required this.value});
  String name;
  String value;
}

/// An HTTP request the native authenticated client executes (`spec/versola-sdk-api.md` section
/// 10). The body is bytes and is buffered whole: the bridge does not stream. There is no origin
/// set: the scope is the edge's origin and cannot be widened.
class VersolaHttpRequestMessage {
  VersolaHttpRequestMessage({
    required this.method,
    required this.url,
    required this.headers,
    this.body,
  });
  String method;
  String url;
  List<VersolaHttpHeaderMessage> headers;
  Uint8List? body;
}

/// The response as the server sent it: status, headers and the whole body. A 3xx, a 429 and a
/// 5xx are responses.
class VersolaHttpResponseMessage {
  VersolaHttpResponseMessage({
    required this.status,
    this.reasonPhrase,
    required this.headers,
    required this.body,
  });
  int status;
  String? reasonPhrase;
  List<VersolaHttpHeaderMessage> headers;
  Uint8List body;
}

sealed class VersolaHttpResult {}

class VersolaHttpOk extends VersolaHttpResult {
  VersolaHttpOk({required this.response});
  VersolaHttpResponseMessage response;
}

/// The SDK refused or could not finish the call: a step-up challenge, a session the edge
/// refused, a nonce that kept changing, a `Configuration` problem (a request that is not a valid
/// HTTP request). The typed taxonomy, as everywhere else.
class VersolaHttpFailure extends VersolaHttpResult {
  VersolaHttpFailure({required this.error});
  VersolaErrorMessage error;
}

/// The request never produced an HTTP response (no route, DNS, TLS, a connection reset, the
/// native client's own timeout). Not an SDK error: the Dart client turns it into `package:http`'s
/// `ClientException`. `exception` is the native exception's class name and nothing else; its
/// message can carry the URL.
class VersolaHttpTransportFailure extends VersolaHttpResult {
  VersolaHttpTransportFailure({required this.exception});
  String exception;
}

/// Dart → native. Every method but `create` takes the `handle` `create` returned: one native
/// client per configuration per process, as the native facades promise.
@HostApi()
abstract class VersolaHostApi {
  /// Validates the configuration and wires (or finds) the native client, and answers with the
  /// handle that names it from now on. The same configuration answers the same handle.
  @async
  VersolaCreateResult create(VersolaConfigurationMessage configuration);

  @async
  VersolaSessionStateResult sessionState(String handle);

  @async
  VersolaVoidResult login(String handle, VersolaLoginOptionsMessage options);

  /// `options` is null when the app passed none: the native side then re-authorizes with the
  /// scopes the session was granted, which is not the same as passing empty options.
  @async
  VersolaVoidResult stepUp(
    String handle,
    List<String> acrValues,
    int? maxAge,
    VersolaLoginOptionsMessage? options,
  );

  @async
  VersolaLogoutResult logout(
    String handle,
    VersolaLogoutOptionsMessage options,
  );

  @async
  VersolaVoidResult refresh(String handle);

  @async
  VersolaClaimsResult claims(String handle);

  @async
  VersolaKeyAttestationResult keyAttestation(String handle);

  /// Executes one request with the native authenticated client (`Versola.call` on Android,
  /// `Versola.session()` on iOS): the token and the DPoP proof are attached, refreshed and
  /// replayed natively and never cross; only the request and the response do.
  @async
  VersolaHttpResult httpRequest(
    String handle,
    VersolaHttpRequestMessage request,
  );
}

/// Native → Dart: the state machine, fed by the native `Flow` / `AsyncStream`; the native
/// collection ends when the subscription does. One channel per client: the handle `create`
/// returned is the Pigeon `instanceName`. The generated stream must be subscribed once per
/// client (a second `EventChannel` of the same name replaces the first's handler); the Dart
/// client shares one subscription among its listeners.
@EventChannelApi()
abstract class VersolaSessionStateEvents {
  VersolaSessionStateMessage sessionStates();
}
