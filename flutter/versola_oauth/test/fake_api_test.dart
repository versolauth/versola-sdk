import 'package:flutter_test/flutter_test.dart';
import 'package:versola_oauth/testing.dart';
import 'package:versola_oauth/versola_oauth.dart';

void main() {
  test('login moves the state to authenticated and records the call', () async {
    final OAuthApi api = FakeOAuthApi();
    final fake = api as FakeOAuthApi;

    await api.login();

    expect(await api.currentSessionState(), SessionState.authenticated);
    expect(fake.calls, ['login']);
  });

  test(
    'a scripted error is thrown from the operation the app would call',
    () async {
      final fake = FakeOAuthApi(state: SessionState.authenticated)
        ..error = const ReauthenticateError(
          ReauthenticateReason.sessionExpired,
          'session expired',
        );

      await expectLater(
        fake.accessToken(),
        throwsA(isA<ReauthenticateError>()),
      );
      expect(fake.calls, ['accessToken']);
    },
  );

  test('logout drops the claims and reports the scripted outcome', () async {
    final fake = FakeOAuthApi(state: SessionState.authenticated);

    final outcome = await fake.logout();

    expect(outcome.sessionEnded, isTrue);
    expect(outcome.tokenRevoked, isTrue);
    expect(await fake.currentSessionState(), SessionState.unauthenticated);
  });

  test(
    'sessionStates yields the current state first, then each change',
    () async {
      final fake = FakeOAuthApi(state: SessionState.authenticated);
      final states = <SessionState>[];
      final subscription = fake.sessionStates().listen(states.add);

      fake.setState(SessionState.refreshing);
      await Future<void>.delayed(Duration.zero);
      await subscription.cancel();

      expect(states, [SessionState.authenticated, SessionState.refreshing]);
    },
  );
}
