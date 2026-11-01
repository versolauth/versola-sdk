import 'dart:async';

import 'api.dart';
import 'errors.dart';
import 'types.dart';

/// A stand-in for `OAuthClient` in an app's tests. It records each call by name in [calls] and
/// returns what the test scripted. It does no protocol work: no PKCE, no validation, no storage.
/// Set [error] to make the next operations fail with a category the app must handle.
final class FakeOAuthApi implements OAuthApi {
  FakeOAuthApi({SessionState state = SessionState.unauthenticated}) {
    _state = state;
  }

  late SessionState _state;
  final _changes = StreamController<SessionState>.broadcast();

  /// The names of the operations called, in order.
  final List<String> calls = [];

  /// Set to make [accessToken], [refresh], [userInfo], [login], [stepUp] and [logout] throw it.
  OAuthError? error;

  /// The token [accessToken] returns; a bearer token by default.
  AccessToken token = const AccessToken(
    value: 'fake-access-token',
    tokenType: 'Bearer',
  );

  /// What [logout] reports.
  LogoutOutcome logoutOutcome = const LogoutOutcome(
    sessionEnded: true,
    tokenRevoked: true,
  );

  /// What [userInfo] returns.
  UserInfo userInfoResult = const UserInfo(subject: 'fake-subject', claims: {});

  /// The claims the fake reports; null when there is no session.
  IdTokenClaims? claimsValue;

  /// Moves the state the way a test needs it, without a sign-in.
  void setState(SessionState state) {
    _state = state;
    _changes.add(state);
  }

  void _record(String name) {
    calls.add(name);
    final error = this.error;
    if (error != null) throw error;
  }

  /// Subscribes to the changes before it reads the state, so no change between the two is missed.
  @override
  Stream<SessionState> sessionStates() {
    late final StreamController<SessionState> controller;
    StreamSubscription<SessionState>? changes;
    controller = StreamController<SessionState>(
      onListen: () {
        changes = _changes.stream.listen(controller.add);
        controller.add(_state);
      },
      onCancel: () => changes?.cancel(),
    );
    return controller.stream;
  }

  @override
  Future<SessionState> currentSessionState() async => _state;

  @override
  Future<IdTokenClaims?> claims() async => claimsValue;

  @override
  Future<void> login([LoginOptions options = const LoginOptions()]) async {
    _record('login');
    setState(SessionState.authenticated);
  }

  @override
  Future<void> stepUp(
    StepUpError challenge, [
    LoginOptions options = const LoginOptions(),
  ]) async {
    _record('stepUp');
    setState(SessionState.authenticated);
  }

  /// Ends the session whatever [error] says: the real logout never fails for a server problem.
  @override
  Future<LogoutOutcome> logout([
    LogoutOptions options = const LogoutOptions(),
  ]) async {
    calls.add('logout');
    claimsValue = null;
    setState(SessionState.unauthenticated);
    return logoutOutcome;
  }

  @override
  Future<AccessToken> accessToken() async {
    _record('accessToken');
    return token;
  }

  @override
  Future<void> refresh() async => _record('refresh');

  @override
  Future<UserInfo> userInfo() async {
    _record('userInfo');
    return userInfoResult;
  }

  @override
  Future<String?> keyAttestation() async {
    calls.add('keyAttestation');
    return null;
  }
}
