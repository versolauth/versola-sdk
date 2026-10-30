import 'dart:async';

import 'package:http/http.dart' as http;

import 'errors.dart';
import 'http_client.dart';
import 'mapping.dart';
import 'messages.g.dart' as bridge;
import 'types.dart';

/// The generic facade of `spec/oauth-sdk-api.md` as a Flutter binding: every call forwards
/// to the native `OAuthClient` (Android) or `VersolaOAuth` (iOS); Dart holds the API shape,
/// argument mapping and the error categories, never protocol logic (`.claude/rules/flutter.md`).
///
/// One native client per configuration per process, as the native facades promise: a second
/// [create] with the same issuer and client id reaches the same native client, and a different
/// configuration for the same pair is refused natively with a [ConfigurationError]. Every
/// method throws an [OAuthError] and nothing else.
final class OAuthClient {
  OAuthClient._(this.configuration, this._handle, this._host);

  final OAuthConfiguration configuration;

  /// What native named this client; every call and the state channel are addressed by it.
  final String _handle;
  final bridge.OAuthHostApi _host;

  /// Validates the configuration natively and wires (or finds) the native client. No network
  /// I/O and no key generation happen here.
  static Future<OAuthClient> create(
    OAuthConfiguration configuration, {
    bridge.OAuthHostApi? host,
  }) async {
    final api = host ?? bridge.OAuthHostApi();
    final result = await guarded(() => api.create(toMessage(configuration)));
    switch (result) {
      case bridge.CreateOk(:final handle):
        return OAuthClient._(configuration, handle, api);
      case bridge.CreateFailure(:final error):
        throw errorFromMessage(error);
    }
  }

  late final StreamController<SessionState> _shared = _sharedStates();
  SessionState? _last;
  StreamSubscription<SessionState>? _native;

  StreamController<SessionState> _sharedStates() {
    late final StreamController<SessionState> controller;
    controller = StreamController<SessionState>.broadcast(
      // The native collection starts with the first listener and ends with the last, so a
      // subscription and the native work have the same lifetime.
      onListen: () {
        _native = bridge
            .sessionStates(instanceName: _handle)
            .map(fromMessage)
            .listen(
              (state) {
                _last = state;
                controller.add(state);
              },
              onError: controller.addError,
              onDone: () => unawaited(controller.close()),
            );
      },
      onCancel: () async {
        final native = _native;
        _native = null;
        _last = null;
        await native?.cancel();
      },
    );
    return controller;
  }

  /// The state machine of `spec/state-machine.md`, any number of listeners, each seeing every
  /// state from the one it subscribes at: the first listener gets the restored state first, a
  /// later one gets the latest state (which it may have missed) and then every change. There is
  /// one native subscription per client, however many listeners; it ends with the last one.
  Stream<SessionState> sessionStates() => Stream<SessionState>.multi((c) {
    final last = _last;
    if (last != null) c.add(last);
    final sub = _shared.stream.listen(c.add, onError: c.addError);
    c.onCancel = sub.cancel;
  }, isBroadcast: true);

  /// The current state, restored first. A method, not a getter: it asks native every time.
  Future<SessionState> currentSessionState() async {
    switch (await guarded(() => _host.sessionState(_handle))) {
      case bridge.SessionStateOk(:final state):
        return fromMessage(state);
      case bridge.SessionStateFailure(:final error):
        throw errorFromMessage(error);
    }
  }

  /// The claims of the validated ID token of this session, or null when there is no session.
  /// A method, not a getter: it asks native every time, so `client.claims != null` cannot
  /// silently be always true.
  Future<IdTokenClaims?> claims() async {
    switch (await guarded(() => _host.claims(_handle))) {
      case bridge.ClaimsOk(:final claims):
        return claims == null ? null : claimsFromMessage(claims);
      case bridge.ClaimsFailure(:final error):
        throw errorFromMessage(error);
    }
  }

  /// Opens the system browser, validates the redirect, exchanges the code, validates the ID
  /// token and persists the grant, natively; `authenticated` is published after the grant is
  /// durably stored. While `authorizing` it is refused: observe [sessionStates] first. A
  /// redirect that reaches a cold-started process finishes the pending request on its own and
  /// the result arrives on [sessionStates] (`spec/oauth-sdk-api.md` section 4).
  Future<void> login([LoginOptions options = const LoginOptions()]) =>
      unwrapVoid(_host.login(_handle, loginOptionsToMessage(options)));

  /// Answers a [StepUpError] by re-authorizing at the authentication context the resource
  /// server asked for; the app then re-issues the refused call.
  Future<void> stepUp(
    StepUpError challenge, [
    LoginOptions options = const LoginOptions(),
  ]) => unwrapVoid(
    _host.stepUp(
      _handle,
      challenge.acrValues,
      challenge.maxAge,
      loginOptionsToMessage(options),
    ),
  );

  /// Signs out (`spec/oauth-sdk-api.md` section 12): revokes, ends the provider's session
  /// through the browser, wipes locally; the wipe is unconditional.
  Future<LogoutOutcome> logout([
    LogoutOptions options = const LogoutOptions(),
  ]) async {
    final result = await guarded(
      () => _host.logout(
        _handle,
        bridge.LogoutOptionsMessage(
          endSession: options.endSession,
          revoke: options.revoke,
        ),
      ),
    );
    switch (result) {
      case bridge.LogoutOk(:final outcome):
        return logoutOutcomeFromMessage(outcome);
      case bridge.LogoutFailure(:final error):
        throw errorFromMessage(error);
    }
  }

  /// The access token, refreshed natively first if it is at or within its refresh skew. The
  /// one credential that crosses the bridge (issue #46 decision 7); never cached in Dart, so
  /// single-flight refresh stays native.
  Future<AccessToken> accessToken() async {
    switch (await guarded(() => _host.accessToken(_handle))) {
      case bridge.AccessTokenOk(:final token):
        return AccessToken(value: token.value, tokenType: token.tokenType);
      case bridge.AccessTokenFailure(:final error):
        throw errorFromMessage(error);
    }
  }

  /// Spends the refresh token now, once, whatever the access token's remaining lifetime.
  Future<void> refresh() => unwrapVoid(_host.refresh(_handle));

  /// `GET` on the UserInfo endpoint with the session's token; `sub` must equal the ID token's.
  Future<UserInfo> userInfo() async {
    switch (await guarded(() => _host.userInfo(_handle))) {
      case bridge.UserInfoOk(:final userInfo):
        return UserInfo(subject: userInfo.subject, claims: userInfo.claims);
      case bridge.UserInfoFailure(:final error):
        throw errorFromMessage(error);
    }
  }

  /// A `package:http` [http.Client] that executes each request **natively**, with the session
  /// attached: the same authenticated client Android (`OAuthClient.call`) and iOS
  /// (`authenticatedSession`) apps use (`spec/oauth-sdk-api.md` section 10). Dart describes the
  /// request and receives the response; the access token, the DPoP key and its proofs, the
  /// single-flight refresh and the origin allow-list stay native, so a DPoP-bound token is usable
  /// from Dart without ever being handed to it.
  ///
  /// For a request to one of [origins] (default: the configuration's `protectedOrigins`; the
  /// origin is `scheme://host[:port]`, any path) the SDK:
  ///
  /// * attaches `Authorization: Bearer` or, for a DPoP-bound token, `Authorization: DPoP` and a
  ///   proof over the final method and URL;
  /// * on a 401 that is neither a step-up nor a nonce demand, refreshes the token once and
  ///   replays the request once (a second 401 is [ReauthenticateError], `sessionRejected`); on
  ///   a DPoP nonce demand retries once with the nonce ([RecoverableError], `nonceLoop`, if the
  ///   server keeps demanding);
  /// * throws [StepUpError] on an RFC 9470 challenge, which the app answers with [stepUp] and
  ///   then re-issues the request.
  ///
  /// A request to any other origin is sent as the app built it, no token and no proof, and its
  /// 401 is returned as it is. Everything else is the response: a 3xx is **not followed**
  /// (`followRedirects` and `maxRedirects` are ignored; `isRedirect` tells the two apart and the
  /// app decides), and a 403, 404, 429 or 5xx comes back with its headers and is never repeated
  /// by the SDK. Errors are [OAuthError]s, never a `PlatformException`; a request that produced no
  /// HTTP response at all (no route, TLS, the native client's own timeout) is a
  /// [http.ClientException].
  ///
  /// **Headers.** The client sets `Authorization` (and `DPoP`) itself on a protected origin: any
  /// value the app supplied under those names is replaced, never sent alongside the SDK's. On
  /// other origins the app's headers go out untouched. Request headers are single-valued, as
  /// `package:http` has it (join a list-valued header with a comma). Response header names are
  /// lower-cased and a repeated name is joined with a comma, so
  /// `response.headersSplitValues` recovers the values; `Set-Cookie` cannot be split reliably
  /// that way, which is `package:http`'s limit. Android reports each value of a repeated header
  /// apart; iOS's `URLSession` already folds them into one, which is equivalent under RFC 9110
  /// section 5.3 except for `Set-Cookie`.
  ///
  /// **Bodies are buffered in memory**, in both directions and in both runtimes (Dart, then the
  /// native client): the bridge carries bytes, not streams, so do not send or fetch a large file
  /// through this client. No limit is enforced beyond the process's memory; use a plain client
  /// to a pre-signed URL for bulk transfer. `Content-Length` of a response may describe the
  /// encoded body the platform has already decoded; `contentLength` is the buffered size.
  ///
  /// **Timeouts and cancellation.** Timeouts are the native client's own configuration (OkHttp's
  /// defaults on Android, the `URLSession`'s on iOS); this plugin sets none. A Dart
  /// `Future.timeout` stops waiting but does not cancel the native call, and `Abortable`
  /// requests are not aborted: `package:http` offers no cancellation the bridge could carry, and
  /// none is invented here.
  ///
  /// [origins] **replaces** the configuration's `protectedOrigins` for this client; it does not
  /// narrow them, so an origin named here that the configuration does not list still gets the
  /// token. That is what `OAuthClient.authenticatedClient(origins)` (Android) and
  /// `authenticatedSession(origins:)` (iOS) do, and the app names both sets in its own code. Name
  /// only origins you mean to send the token to.
  ///
  /// [origins] is validated natively on the first request, which fails before anything is sent
  /// with [ConfigurationError] (`invalidConfiguration`) when the set (or, with none given, the
  /// configured `protectedOrigins`) is empty, has a non-`https` origin (`http` is allowed on a
  /// loopback host) or an entry with a path, query or fragment.
  ///
  /// **Composing.** This client is a `BaseClient`: wrap it with the app's own interceptors, and
  /// keep it the *innermost* one, because the proof depends on the final method and URL:
  ///
  /// ```dart
  /// class LoggingClient extends http.BaseClient {
  ///   LoggingClient(this._inner);
  ///   final http.Client _inner;
  ///   @override
  ///   Future<http.StreamedResponse> send(http.BaseRequest request) async {
  ///     request.headers['x-request-id'] = newId(); // the app's rewrite runs first
  ///     return _inner.send(request);
  ///   }
  /// }
  ///
  /// // package:http/retry.dart. The SDK never repeats the app's request on a status (it cannot
  /// // know the call was idempotent, spec/retry-policy.md), so a retry here is the app's own
  /// // decision: only methods that are safe to repeat, and never a POST.
  /// final client = RetryClient(
  ///   LoggingClient(oauth.httpClient()),
  ///   when: (r) => r.statusCode == 503 && const {'GET', 'HEAD'}.contains(r.request?.method),
  /// );
  /// try {
  ///   final response = await client.get(Uri.https('api.example.com', '/items'));
  /// } on StepUpError catch (challenge) {
  ///   await oauth.stepUp(challenge); // then repeat the request
  /// }
  /// ```
  ///
  /// With `dio`, a small adapter makes this client dio's transport (dio's own interceptors then
  /// wrap it, so the authentication step is still last; `package:dio` is the app's dependency,
  /// not this plugin's). A thrown [OAuthError] arrives as the `error` of a `DioException`:
  ///
  /// ```dart
  /// class VersolaAdapter implements HttpClientAdapter {
  ///   VersolaAdapter(this._client);
  ///   final http.Client _client;
  ///
  ///   @override
  ///   Future<ResponseBody> fetch(RequestOptions options,
  ///       Stream<Uint8List>? requestStream, Future<void>? cancelFuture) async {
  ///     final request = http.Request(options.method, options.uri);
  ///     options.headers.forEach((name, value) => request.headers[name] = '$value');
  ///     if (requestStream != null) {
  ///       request.bodyBytes = Uint8List.fromList(
  ///           [for (final chunk in await requestStream.toList()) ...chunk]);
  ///     }
  ///     final response = await _client.send(request);
  ///     return ResponseBody(response.stream.cast<Uint8List>(), response.statusCode,
  ///         headers: {
  ///           for (final entry in response.headers.entries) entry.key: [entry.value],
  ///         },
  ///         statusMessage: response.reasonPhrase,
  ///         isRedirect: response.isRedirect);
  ///   }
  ///
  ///   @override
  ///   void close({bool force = false}) => _client.close();
  /// }
  ///
  /// final dio = Dio()..httpClientAdapter = VersolaAdapter(oauth.httpClient());
  /// ```
  ///
  /// Each call returns a new client; close it when done.
  http.Client httpClient({Set<String>? origins}) =>
      AuthenticatedHttpClient(_host, _handle, origins);

  /// Which key tier the DPoP key reached (`secureEnclave`, `strongBox`, `trustedEnvironment`,
  /// `software`), or null under bearer. Asking this generates the key natively, so under
  /// `TokenBinding.dpopRequireHardware` on a device that cannot honour it this throws a
  /// [ConfigurationError] (`hardwareBindingUnavailable`).
  Future<String?> keyAttestation() async {
    switch (await guarded(() => _host.keyAttestation(_handle))) {
      case bridge.KeyAttestationOk(:final tier):
        return tier;
      case bridge.KeyAttestationFailure(:final error):
        throw errorFromMessage(error);
    }
  }
}
