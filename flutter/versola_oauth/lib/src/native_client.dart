import 'dart:async';

import 'package:flutter/services.dart';
import 'package:http/http.dart' as http;

import 'client.dart';
import 'errors.dart';
import 'http_client.dart';
import 'mapping.dart';
import 'messages.g.dart' as bridge;
import 'types.dart';

/// The [OAuthClient] that forwards every call to the native SDK through the Pigeon bridge.
/// Lives apart from `client.dart`, which is exported: no generated type may appear in a
/// public signature (`.claude/rules/flutter.md`).
final class NativeOAuthClient implements OAuthClient {
  NativeOAuthClient._(this.configuration, this._handle, this._host);

  @override
  final OAuthConfiguration configuration;

  /// What native named this client; every call and the state channel are addressed by it.
  final String _handle;
  final bridge.OAuthHostApi _host;

  static Future<OAuthClient> create(OAuthConfiguration configuration) =>
      createWithHost(configuration, bridge.OAuthHostApi());

  /// [create] with the native host replaced: the tests' seam.
  static Future<OAuthClient> createWithHost(
    OAuthConfiguration configuration,
    bridge.OAuthHostApi api,
  ) async {
    final result = await guarded(() => api.create(toMessage(configuration)));
    switch (result) {
      case bridge.CreateOk(:final handle):
        return NativeOAuthClient._(configuration, handle, api);
      case bridge.CreateFailure(:final error):
        throw errorFromMessage(error);
    }
  }

  @override
  Stream<SessionState> sessionStates() => Stream<SessionState>.multi((c) {
    final hub = _StateHub.of(_handle)..add(c);
    c.onCancel = () => hub.remove(c);
  }, isBroadcast: true);

  @override
  Future<SessionState> currentSessionState() async {
    switch (await guarded(() => _host.sessionState(_handle))) {
      case bridge.SessionStateOk(:final state):
        return fromMessage(state);
      case bridge.SessionStateFailure(:final error):
        throw errorFromMessage(error);
    }
  }

  @override
  Future<IdTokenClaims?> claims() async {
    switch (await guarded(() => _host.claims(_handle))) {
      case bridge.ClaimsOk(:final claims):
        return claims == null ? null : claimsFromMessage(claims);
      case bridge.ClaimsFailure(:final error):
        throw errorFromMessage(error);
    }
  }

  @override
  Future<void> login([LoginOptions? options]) => unwrapVoid(
    _host.login(_handle, loginOptionsToMessage(options ?? LoginOptions())),
  );

  @override
  Future<void> stepUp(StepUpError challenge, [LoginOptions? options]) =>
      unwrapVoid(
        _host.stepUp(
          _handle,
          challenge.acrValues,
          challenge.maxAge,
          loginOptionsToMessage(options ?? LoginOptions()),
        ),
      );

  @override
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

  @override
  Future<AccessToken> accessToken() async {
    switch (await guarded(() => _host.accessToken(_handle))) {
      case bridge.AccessTokenOk(:final token):
        return AccessToken(value: token.value, tokenType: token.tokenType);
      case bridge.AccessTokenFailure(:final error):
        throw errorFromMessage(error);
    }
  }

  @override
  Future<void> refresh() => unwrapVoid(_host.refresh(_handle));

  @override
  Future<UserInfo> userInfo() async {
    switch (await guarded(() => _host.userInfo(_handle))) {
      case bridge.UserInfoOk(:final userInfo):
        return UserInfo(subject: userInfo.subject, claims: userInfo.claims);
      case bridge.UserInfoFailure(:final error):
        throw errorFromMessage(error);
    }
  }

  @override
  http.Client httpClient({Set<String>? origins}) =>
      AuthenticatedHttpClient(_host, _handle, origins);

  @override
  Future<String?> keyAttestation() async {
    switch (await guarded(() => _host.keyAttestation(_handle))) {
      case bridge.KeyAttestationOk(:final tier):
        return tier;
      case bridge.KeyAttestationFailure(:final error):
        throw errorFromMessage(error);
    }
  }
}

/// Wiring for the tests: [OAuthClient.create] with the native host replaced. Lives under `src/`,
/// which the package does not export, so the bridge type stays out of the public API.
Future<OAuthClient> createOAuthClientWithHost(
  OAuthConfiguration configuration,
  bridge.OAuthHostApi host,
) => NativeOAuthClient.createWithHost(configuration, host);

/// One native subscription per native client, shared by every [NativeOAuthClient] and every
/// listener that reaches it.
///
/// Pigeon's stream is single-listener per channel *name*: a second `EventChannel` of the same
/// name replaces the first's handler, and a cancel on either clears the native sink for both.
/// Two `OAuthClient`s with one handle (the native facades hand out one client per
/// configuration, so `create` twice answers the same handle) must therefore not each own a
/// subscription; the registry makes the hub, not the client, the owner.
final class _StateHub {
  _StateHub._(this._handle);

  static final Map<String, _StateHub> _hubs = {};

  static _StateHub of(String handle) =>
      _hubs.putIfAbsent(handle, () => _StateHub._(handle));

  final String _handle;
  final Set<MultiStreamController<SessionState>> _listeners = {};
  SessionState? _last;
  StreamSubscription<SessionState>? _native;

  void add(MultiStreamController<SessionState> c) {
    // A later listener gets the latest state, which it may have missed, then every change.
    final last = _last;
    if (last != null) c.add(last);
    _listeners.add(c);
    _native ??= _open();
  }

  void remove(MultiStreamController<SessionState> c) {
    _listeners.remove(c);
    if (_listeners.isNotEmpty) return;
    // The native collection starts with the first listener and ends with the last.
    final native = _native;
    _native = null;
    _last = null;
    _release();
    unawaited(native?.cancel());
  }

  StreamSubscription<SessionState> _open() => _channel(_handle)
      .receiveBroadcastStream()
      .map((dynamic event) => fromMessage(event as bridge.SessionStateMessage))
      .listen(
        (state) {
          _last = state;
          for (final l in _listeners.toList()) {
            l.add(state);
          }
        },
        // Whatever the native side raised reaches the app as an [OAuthError]; the
        // subscription stays up (an error is not the end of the stream).
        onError: (Object error) {
          final typed = asOAuthError(error);
          for (final l in _listeners.toList()) {
            l.addError(typed);
          }
        },
        // The native stream ended: so do the listeners' (a stream that never completes would
        // park an `await for` forever).
        onDone: () {
          final listeners = _listeners.toList();
          _listeners.clear();
          _native = null;
          _last = null;
          _release();
          for (final l in listeners) {
            l.close();
          }
        },
      );

  void _release() {
    if (identical(_hubs[_handle], this)) _hubs.remove(_handle);
  }
}

EventChannel _channel(String handle) => EventChannel(
  'dev.flutter.pigeon.versola_oauth.SessionStateEvents.sessionStates'
  '${handle.isEmpty ? '' : '.$handle'}',
  const _TolerantCodec(bridge.pigeonMethodCodec),
);

/// [bridge.pigeonMethodCodec] that turns an event it cannot decode (an enum index from a newer
/// native side, a value type it does not know) into a `PlatformException`, which
/// `EventChannel` delivers as a stream error. Without it the decode failure is thrown inside
/// the engine's message handler and the app never hears of it.
final class _TolerantCodec implements MethodCodec {
  const _TolerantCodec(this._inner);
  final MethodCodec _inner;

  @override
  dynamic decodeEnvelope(ByteData envelope) {
    try {
      return _inner.decodeEnvelope(envelope);
    } on PlatformException {
      rethrow;
    } catch (e) {
      throw PlatformException(
        code: 'undecodable-event',
        message: 'the native event could not be decoded (${e.runtimeType})',
      );
    }
  }

  @override
  ByteData encodeErrorEnvelope({
    required String code,
    String? message,
    dynamic details,
  }) => _inner.encodeErrorEnvelope(
    code: code,
    message: message,
    details: details,
  );

  @override
  ByteData encodeMethodCall(MethodCall methodCall) =>
      _inner.encodeMethodCall(methodCall);

  @override
  ByteData encodeSuccessEnvelope(dynamic result) =>
      _inner.encodeSuccessEnvelope(result);

  @override
  MethodCall decodeMethodCall(ByteData? methodCall) =>
      _inner.decodeMethodCall(methodCall);
}
