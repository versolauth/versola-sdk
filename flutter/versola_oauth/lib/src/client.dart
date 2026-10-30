import 'dart:async';

import 'errors.dart';
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
