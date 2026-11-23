import 'package:flutter/foundation.dart'
    show TargetPlatform, defaultTargetPlatform, kIsWeb;
import 'package:http/http.dart' as http;
import 'package:versola_oauth/versola_oauth.dart'
    show IdTokenClaims, LogoutOptions, LogoutOutcome, SessionState, StepUpError;

import 'api.dart';
import 'configuration.dart';
import 'native_client.dart';

/// The `Versola` facade of `spec/versola-sdk-api.md` as a Flutter binding: every call forwards to
/// the native `Versola` (Android, `versola.sdk`; iOS, `VersolaSDK`); Dart holds the API shape,
/// argument mapping and the error categories, never protocol logic (`.claude/rules/flutter.md`).
///
/// One native client per edge, issuer and client id per process, as the native facades promise: a
/// second [create] with the same configuration reaches the same native client, and a different
/// one for the same triple is refused natively with a `ConfigurationError`
/// (`invalidConfiguration`). Every method throws an `OAuthError` and nothing else (a duration
/// finer than the bridge's units is an [ArgumentError]: no native call could repair it).
///
/// An interface, so an app can fake it in its own tests (`implements Versola`); the
/// implementation is private to the plugin.
abstract interface class Versola implements VersolaApi {
  /// The configuration this client was created with.
  VersolaConfiguration get configuration;

  /// Validates the configuration natively and wires (or finds) the native client. No network I/O
  /// and no key generation happen here, and there is no discovery to run later.
  ///
  /// Throws [UnsupportedError] off Android and iOS: the plugin is a binding over those two
  /// native SDKs and has nothing to forward to on the web or on a desktop platform.
  static Future<Versola> create(VersolaConfiguration configuration) async {
    if (kIsWeb ||
        (defaultTargetPlatform != TargetPlatform.android &&
            defaultTargetPlatform != TargetPlatform.iOS)) {
      throw UnsupportedError(
        'versola supports Android and iOS only '
        '(running on ${kIsWeb ? 'the web' : defaultTargetPlatform.name})',
      );
    }
    return NativeVersola.create(configuration);
  }

  /// The state machine of `spec/state-machine.md`, any number of listeners, each seeing every
  /// state from the one it subscribes at: the first listener gets the restored state first, a
  /// later one gets the latest state (which it may have missed) and then every change. There is
  /// one native subscription per native client, however many listeners and however many
  /// [Versola]s reach it; it ends with the last listener.
  @override
  Stream<SessionState> sessionStates();

  /// The current state, restored first. A method, not a getter: it asks native every time.
  @override
  Future<SessionState> currentSessionState();

  /// The claims of the validated ID token of this session, or null when there is no session. Its
  /// signature is not verified (`spec/versola-sdk-api.md` section 9): use it to show who is signed
  /// in, not to authorize anything.
  @override
  Future<IdTokenClaims?> claims();

  /// Opens the system browser, validates the redirect, redeems the code through the edge, checks
  /// the ID token and persists the grant, natively; `authenticated` is published after the grant
  /// is durably stored. A second `login()` while one is in flight joins it when it asks for the
  /// same thing: both futures complete with the one result and one browser opens. One that asks
  /// for something else is refused with a `ConfigurationError` (`invalidConfiguration`): observe
  /// [sessionStates] before asking. A redirect that reaches a cold-started process finishes the
  /// pending request on its own and the result arrives on [sessionStates]. A sign-in that is not
  /// finished when the edge's lifetime for it ends is
  /// `RecoverableError(pendingRequestExpired)`.
  ///
  /// **`edge_client_unknown`.** An edge that answers `404` to a native call (the client id is not
  /// registered there) raises `Configuration(EdgeClientUnknown)` natively. That case has no value
  /// in `ConfigurationDetail`, so it arrives as a `ConfigurationError` whose `detail` is
  /// `ConfigurationDetail.unknown`, whose `text` is `edge_client_unknown` and whose `sdkCode` is
  /// `configuration.edge_client_unknown`. Recognise it with
  /// `error.sdkCode == 'configuration.edge_client_unknown'`; nothing else about it needs
  /// parsing, and no retry fixes it.
  @override
  Future<void> login([LoginOptions? options]);

  /// Answers a `StepUpError` by signing the user in again at the authentication context it names
  /// (`acrValues` and `maxAge` come from the challenge); the app then re-issues the refused call.
  ///
  /// Without [options] the native side uses the scopes the session was **granted**, which it
  /// remembers; that is not the same as passing `LoginOptions()`, which asks for `openid` and
  /// `offline_access` alone, and the two are not interchangeable. Dart sends "no options" as it
  /// is. The step-up must come back as the user of the session: another user is
  /// `RecoverableError(accountMismatch)`, nothing of that sign-in is kept and the session is as
  /// it was.
  @override
  Future<void> stepUp(StepUpError challenge, [LoginOptions? options]);

  /// Signs out (`spec/versola-sdk-api.md` section 12): revokes through the edge, ends the
  /// issuer's session through the browser, wipes locally; the wipe is unconditional.
  @override
  Future<LogoutOutcome> logout([LogoutOptions options = const LogoutOptions()]);

  /// Spends the refresh token now, once, however many callers ask.
  @override
  Future<void> refresh();

  /// A `package:http` [http.Client] that executes each request **natively**, with the session
  /// attached: `Versola.call` on Android and `Versola.session()` on iOS
  /// (`spec/versola-sdk-api.md` section 10). Dart describes the request and receives the
  /// response; the access token, the DPoP key and its proofs and the single-flight refresh stay
  /// native, so a DPoP-bound token is usable from Dart without ever being handed to it.
  ///
  /// The scope is **the edge's origin and cannot be widened**: a request to the edge gets the
  /// token and a proof over the final method and URL, and a request to any other origin is sent
  /// as the app built it, no token and no proof, its 401 returned as it is. There is no
  /// `origins` parameter on purpose.
  ///
  /// For a request to the edge the SDK:
  ///
  /// * attaches `Authorization: DPoP` and a proof;
  /// * on a 401 that is neither a step-up nor a nonce demand, refreshes the token once and
  ///   replays the request once (a second 401 is `ReauthenticateError(sessionRejected)`); on a
  ///   DPoP nonce demand retries once with the nonce (`RecoverableError(nonceLoop)` if the edge
  ///   keeps demanding);
  /// * throws `StepUpError` on an RFC 9470 challenge, which the app answers with [stepUp] and
  ///   then re-issues the request.
  ///
  /// Everything else is the response: a 3xx is **not followed** (`followRedirects` and
  /// `maxRedirects` are ignored; `isRedirect` tells the two apart and the app decides), and a 403,
  /// 404, 429 or 5xx comes back with its headers and is never repeated by the SDK. Errors are
  /// `OAuthError`s, never a `PlatformException`; a request that produced no HTTP response at all
  /// (no route, TLS, the native client's own timeout) is a [http.ClientException] that names only
  /// the native exception's class.
  ///
  /// **Headers.** The client sets `Authorization` and `DPoP` itself on the edge: any value the app
  /// supplied under those names is replaced. On other origins the app's headers go out untouched.
  /// Request headers are single-valued, as `package:http` has it. Response header names are
  /// lower-cased and a repeated name is joined with a comma, so `response.headersSplitValues`
  /// recovers the values (`Set-Cookie` cannot be split reliably that way: `package:http`'s limit).
  ///
  /// **Bodies are buffered in memory**, in both directions and in both runtimes: the bridge
  /// carries bytes, not streams, so do not send or fetch a large file through this client.
  ///
  /// **Timeouts and cancellation.** Timeouts are the native client's own configuration; this
  /// plugin sets none. A Dart `Future.timeout` stops waiting but does not cancel the native call,
  /// and `Abortable` requests are not aborted.
  ///
  /// **Composing.** This client is a `BaseClient`: wrap it with the app's own interceptors, and
  /// keep it the *innermost* one, because the proof depends on the final method and URL. The
  /// SDK never repeats the app's request on a status, so a retry wrapper is the app's own
  /// decision, and never for a POST.
  ///
  /// Each call returns a new client; close it when done.
  http.Client httpClient();

  /// Which key tier the DPoP key reached (`secureEnclave`, `strongBox`, `trustedEnvironment`,
  /// `software`). Asking this generates the key natively, so with `requireHardwareKey` on a device
  /// that cannot honour it this throws a `ConfigurationError` (`hardwareBindingUnavailable`).
  @override
  Future<String?> keyAttestation();
}
