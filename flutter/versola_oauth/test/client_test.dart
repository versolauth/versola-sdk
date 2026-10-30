import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:versola_oauth/src/messages.g.dart';
import 'package:versola_oauth/versola_oauth.dart';

/// A scripted host: records what crossed and answers from a queue (an Exception in the queue is
/// thrown, as a channel failure would be). The bridge is mocked, so these tests prove the Dart
/// shape and the error categories, not the native SDKs (`testing.md`).
class FakeHost extends OAuthHostApi {
  final List<String> calls = [];
  final List<Object?> answers = [];

  T _next<T>(String call) {
    calls.add(call);
    final answer = answers.removeAt(0);
    if (answer is Exception) throw answer;
    return answer as T;
  }

  @override
  Future<CreateResult> create(ConfigurationMessage configuration) async =>
      _next('create:${configuration.clientId}');
  @override
  Future<SessionStateResult> sessionState(String handle) async =>
      _next('sessionState');
  @override
  Future<VoidResult> login(String handle, LoginOptionsMessage options) async =>
      _next('login:${options.prompt?.name}');
  @override
  Future<VoidResult> stepUp(
    String handle,
    List<String> acrValues,
    int? maxAge,
    LoginOptionsMessage options,
  ) async => _next('stepUp:${acrValues.join(",")}:$maxAge');
  @override
  Future<LogoutResult> logout(
    String handle,
    LogoutOptionsMessage options,
  ) async => _next('logout:${options.endSession}:${options.revoke}');
  @override
  Future<AccessTokenResult> accessToken(String handle) async =>
      _next('accessToken');
  @override
  Future<VoidResult> refresh(String handle) async => _next('refresh');
  @override
  Future<ClaimsResult> claims(String handle) async => _next('claims');
  @override
  Future<UserInfoResult> userInfo(String handle) async => _next('userInfo');
  @override
  Future<KeyAttestationResult> keyAttestation(String handle) async =>
      _next('keyAttestation');

  /// Every request the HTTP client sent across, in order.
  final List<HttpRequestMessage> requests = [];
  @override
  Future<HttpResult> httpRequest(
    String handle,
    HttpRequestMessage request,
  ) async {
    requests.add(request);
    return _next('httpRequest');
  }
}

const configuration = OAuthConfiguration(
  issuer: 'https://id.example.com',
  clientId: 'app',
  redirectUri: 'https://app.example.com/oauth',
);

ErrorMessage reauth() => ErrorMessage(
  category: ErrorCategoryMessage.reauthenticate,
  kind: 'grantRejected',
  message: 'reauthenticate: GrantRejected',
);

Future<OAuthClient> created(FakeHost host, {String handle = 'h1'}) async {
  host.answers.insert(0, CreateOk(handle: handle));
  return OAuthClient.create(configuration, host: host);
}

/// The event channel the generated `sessionStates` opens for [handle], with the native side
/// scripted: `sink` is the native sink once somebody listens, the counters say how often.
class NativeStates {
  NativeStates(String handle) {
    final channel = EventChannel(
      'dev.flutter.pigeon.versola_oauth.SessionStateEvents.sessionStates.$handle',
      pigeonMethodCodec,
    );
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockStreamHandler(
          channel,
          MockStreamHandler.inline(
            onListen: (args, events) {
              listens++;
              sink = events;
            },
            onCancel: (args) => cancels++,
          ),
        );
  }
  int listens = 0;
  int cancels = 0;
  MockStreamHandlerEventSink? sink;
  void emit(SessionStateMessage state) => sink!.success(state);
}

Future<void> settle() => Future<void>.delayed(Duration.zero);

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  test(
    'create answers with the handle native chose and keys the client by it',
    () async {
      final host = FakeHost();
      final client = await created(host, handle: 'client-7');
      expect(client.configuration, configuration);
      expect(host.calls, ['create:app']);
    },
  );

  test('a configuration the native side refuses is a ConfigurationError from create', () async {
    final host = FakeHost()
      ..answers.add(
        CreateFailure(
          error: ErrorMessage(
            category: ErrorCategoryMessage.configuration,
            kind: 'invalidConfiguration',
            message: 'configuration: bad',
            detail: 'redirectUri must be absolute',
          ),
        ),
      );
    await expectLater(
      OAuthClient.create(
        const OAuthConfiguration(
          issuer: 'https://other.example.com',
          clientId: 'app',
          redirectUri: 'nope',
        ),
        host: host,
      ),
      throwsA(
        isA<ConfigurationError>()
            .having(
              (e) => e.detail,
              'detail',
              ConfigurationDetail.invalidConfiguration,
            )
            .having((e) => e.text, 'text', 'redirectUri must be absolute'),
      ),
    );
  });

  test(
    'login forwards the options and a failure arrives as its category',
    () async {
      final host = FakeHost();
      final client = await created(host);
      host.answers.addAll([VoidOk(), VoidFailure(error: reauth())]);
      await client.login(const LoginOptions(prompt: Prompt.login));
      expect(host.calls.last, 'login:login');
      await expectLater(
        client.login(),
        throwsA(
          isA<ReauthenticateError>().having(
            (e) => e.reason,
            'reason',
            ReauthenticateReason.grantRejected,
          ),
        ),
      );
    },
  );

  test(
    'stepUp sends the challenge back as the native side raised it',
    () async {
      final host = FakeHost();
      final client = await created(host);
      host.answers.add(VoidOk());
      await client.stepUp(
        const StepUpError('step-up', acrValues: ['urn:acr:mfa'], maxAge: 60),
      );
      expect(host.calls.last, 'stepUp:urn:acr:mfa:60');
    },
  );

  test('accessToken returns the token or throws the typed error, and caches nothing', () async {
    final host = FakeHost();
    final client = await created(host);
    host.answers.addAll([
      AccessTokenOk(
        token: AccessTokenMessage(value: 'at-1', tokenType: 'DPoP'),
      ),
      AccessTokenOk(
        token: AccessTokenMessage(value: 'at-2', tokenType: 'DPoP'),
      ),
      AccessTokenFailure(error: reauth()),
    ]);
    expect((await client.accessToken()).value, 'at-1');
    expect((await client.accessToken()).value, 'at-2');
    await expectLater(
      client.accessToken(),
      throwsA(isA<ReauthenticateError>()),
    );
    expect(host.calls.where((c) => c == 'accessToken'), hasLength(3));
  });

  test('logout, claims, userInfo, sessionState and keyAttestation map their answers', () async {
    final host = FakeHost();
    final client = await created(host);
    host.answers.addAll([
      LogoutOk(
        outcome: LogoutOutcomeMessage(sessionEnded: true, tokenRevoked: false),
      ),
      ClaimsOk(
        claims: IdTokenClaimsMessage(
          subject: 'alice',
          issuer: 'https://id.example.com',
          audience: ['app'],
          issuedAtEpochSeconds: 1700000000,
          expiresAtEpochSeconds: 1700000300,
          acr: 'urn:acr:mfa',
          amr: ['pwd'],
          all: {'sub': 'alice'},
        ),
      ),
      ClaimsOk(),
      UserInfoOk(
        userInfo: UserInfoMessage(subject: 'alice', claims: {'name': 'Alice'}),
      ),
      SessionStateOk(state: SessionStateMessage.authenticated),
      KeyAttestationOk(tier: 'strongBox'),
      KeyAttestationOk(),
    ]);
    final outcome = await client.logout(const LogoutOptions(revoke: false));
    expect(host.calls.last, 'logout:true:false');
    expect(outcome.sessionEnded, isTrue);
    final claims = await client.claims();
    expect(claims?.expiresAt, DateTime.utc(2023, 11, 14, 22, 18, 20));
    expect(claims?.acr, 'urn:acr:mfa');
    expect(await client.claims(), isNull);
    expect((await client.userInfo()).claims['name'], 'Alice');
    expect(await client.currentSessionState(), SessionState.authenticated);
    expect(await client.keyAttestation(), 'strongBox');
    expect(await client.keyAttestation(), isNull);
  });

  test('keyAttestation without hardware is a ConfigurationError, not a PlatformException', () async {
    final host = FakeHost();
    final client = await created(host);
    host.answers.add(
      KeyAttestationFailure(
        error: ErrorMessage(
          category: ErrorCategoryMessage.configuration,
          kind: 'hardwareBindingUnavailable',
          message: 'configuration: HardwareBindingUnavailable',
          detail: 'software-backed key',
        ),
      ),
    );
    await expectLater(
      client.keyAttestation(),
      throwsA(
        isA<ConfigurationError>().having(
          (e) => e.detail,
          'detail',
          ConfigurationDetail.hardwareBindingUnavailable,
        ),
      ),
    );
  });

  test('a channel failure is a ConfigurationError carrying the code and none of the native text', () async {
    final host = FakeHost();
    final client = await created(host);
    host.answers.addAll([
      PlatformException(
        code: 'channel-error',
        message: 'java.lang.IllegalStateException: refresh_token=do-not-leak',
        details: 'stack trace',
      ),
      PlatformException(code: 'channel-error'),
      PlatformException(code: 'channel-error'),
    ]);
    for (final call in <Future<Object?> Function()>[
      client.refresh,
      client.accessToken,
      client.claims,
    ]) {
      await expectLater(
        call(),
        throwsA(
          isA<ConfigurationError>()
              .having((e) => e.text, 'text', 'bridge failure: channel-error')
              .having(
                (e) => e.message,
                'message',
                isNot(contains('do-not-leak')),
              )
              .having(
                (e) => e.toString(),
                'toString',
                isNot(contains('do-not-leak')),
              ),
        ),
      );
    }
    host.answers.add(PlatformException(code: 'channel-error'));
    await expectLater(
      OAuthClient.create(configuration, host: host),
      throwsA(isA<ConfigurationError>()),
    );
  });

  group('sessionStates', () {
    test('maps the event channel of this client', () async {
      final client = await created(FakeHost(), handle: 'h-map');
      final native = NativeStates('h-map');
      final seen = <SessionState>[];
      final sub = client.sessionStates().listen(seen.add);
      await settle();
      native
        ..emit(SessionStateMessage.unauthenticated)
        ..emit(SessionStateMessage.authorizing)
        ..emit(SessionStateMessage.authenticated);
      await settle();
      expect(seen, [
        SessionState.unauthenticated,
        SessionState.authorizing,
        SessionState.authenticated,
      ]);
      await sub.cancel();
    });

    test(
      'two listeners both see every state and share one native subscription',
      () async {
        final client = await created(FakeHost(), handle: 'h-two');
        final native = NativeStates('h-two');
        final a = <SessionState>[];
        final b = <SessionState>[];
        final subA = client.sessionStates().listen(a.add);
        await settle();
        native.emit(SessionStateMessage.unauthenticated);
        await settle();
        // A second listener joins late: it is told the latest state, then every change.
        final subB = client.sessionStates().listen(b.add);
        await settle();
        native.emit(SessionStateMessage.authenticated);
        await settle();
        expect(a, [SessionState.unauthenticated, SessionState.authenticated]);
        expect(b, [SessionState.unauthenticated, SessionState.authenticated]);
        expect(native.listens, 1);

        // One cancelling leaves the other running, and the native collection alive.
        await subB.cancel();
        await settle();
        expect(native.cancels, 0);
        native.emit(SessionStateMessage.loggingOut);
        await settle();
        expect(a.last, SessionState.loggingOut);
        expect(b, hasLength(2));

        // The last one leaving ends the native collection; a new listener starts a fresh one
        // and gets the restored state rather than a stale one.
        await subA.cancel();
        await settle();
        expect(native.cancels, 1);
        final c = <SessionState>[];
        final subC = client.sessionStates().listen(c.add);
        await settle();
        expect(native.listens, 2);
        expect(c, isEmpty);
        native.emit(SessionStateMessage.unauthenticated);
        await settle();
        expect(c, [SessionState.unauthenticated]);
        await subC.cancel();
      },
    );
  });
}
