import 'dart:async';

import 'errors.dart';
import 'mapping.dart';
import 'messages.g.dart' as bridge;
import 'types.dart';

/// The generic facade of `spec/oauth-sdk-api.md` as a Flutter binding: every call forwards
/// to the native `OAuthClient` (Android) or `VersolaOAuth` (iOS); Dart holds the API shape,
/// argument mapping and the error categories, never protocol logic (`.claude/rules/flutter.md`).
///
/// One instance per configuration per process, as the native facades promise: a second
/// `create` with the same issuer and client id returns the first, and a different configuration
/// for the same pair is refused natively with a `ConfigurationError`.
final class OAuthClient {
  OAuthClient._(this.configuration, this._handle, this._host);

  final OAuthConfiguration configuration;
  final String _handle;
  final bridge.OAuthHostApi _host;

  static final Map<String, OAuthClient> _clients = <String, OAuthClient>{};

  /// Validates the configuration natively and wires the native client. No network I/O and no
  /// key generation happen here.
  static Future<OAuthClient> create(
    OAuthConfiguration configuration, {
    bridge.OAuthHostApi? host,
  }) async {
    final api = host ?? bridge.OAuthHostApi();
    final handle = handleFor(configuration);
    final existing = _clients[handle];
    if (existing != null && identical(existing._host, api)) {
      // The native side holds the one instance and refuses a different configuration for
      // the same handle; asking it again is what keeps Dart and native in step.
      await unwrapVoid(api.create(handle, toMessage(configuration)));
      return existing;
    }
    await unwrapVoid(api.create(handle, toMessage(configuration)));
    final client = OAuthClient._(configuration, handle, api);
    _clients[handle] = client;
    return client;
  }

  /// The state machine of `spec/state-machine.md`, one stream per listener; the first value is
  /// the restored state. The native collection ends when the subscription does.
  Stream<SessionState> sessionStates() =>
      bridge.sessionStates(instanceName: _handle).map(fromMessage);

  /// The current state, restored first.
  Future<SessionState> get sessionState async =>
      fromMessage(await _host.sessionState(_handle));

  /// The claims of the validated ID token of this session, or null when there is no session.
  Future<IdTokenClaims?> get claims async {
    final message = await _host.claims(_handle);
    return message == null ? null : claimsFromMessage(message);
  }

  /// Opens the system browser, validates the redirect, exchanges the code, validates the ID
  /// token and persists the grant, natively; `authenticated` is published after the grant is
  /// durably stored. While `authorizing` it is refused: observe [sessionStates] first.
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

  /// Finishes an authorization that outlived the process that started it (scenario 12).
  Future<void> resumePendingAuthorization() =>
      unwrapVoid(_host.resumePendingAuthorization(_handle));

  /// Signs out (`spec/oauth-sdk-api.md` section 12): revokes, ends the provider's session
  /// through the browser, wipes locally; the wipe is unconditional.
  Future<LogoutOutcome> logout([
    LogoutOptions options = const LogoutOptions(),
  ]) async => logoutOutcomeFromMessage(
    await _host.logout(
      _handle,
      bridge.LogoutOptionsMessage(
        endSession: options.endSession,
        revoke: options.revoke,
      ),
    ),
  );

  /// The access token, refreshed natively first if it is at or within its refresh skew. The
  /// one credential that crosses the bridge (issue #46 decision 7); never cached in Dart, so
  /// single-flight refresh stays native.
  Future<AccessToken> accessToken() async {
    final result = await _host.accessToken(_handle);
    return switch (result) {
      bridge.AccessTokenOk(:final token) => AccessToken(
        value: token.value,
        tokenType: token.tokenType,
      ),
      bridge.AccessTokenFailure(:final error) => throw errorFromMessage(error),
    };
  }

  /// Spends the refresh token now, once, whatever the access token's remaining lifetime.
  Future<void> refresh() => unwrapVoid(_host.refresh(_handle));

  /// `GET` on the UserInfo endpoint with the session's token; `sub` must equal the ID token's.
  Future<UserInfo> userInfo() async {
    final result = await _host.userInfo(_handle);
    return switch (result) {
      bridge.UserInfoOk(:final userInfo) => UserInfo(
        subject: userInfo.subject,
        claims: userInfo.claims,
      ),
      bridge.UserInfoFailure(:final error) => throw errorFromMessage(error),
    };
  }

  /// Which key tier the DPoP key reached (`secureEnclave`, `strongBox`, `trustedEnvironment`,
  /// `software`), or null under bearer. Asking this generates the key natively.
  Future<String?> keyAttestation() => _host.keyAttestation(_handle);
}
