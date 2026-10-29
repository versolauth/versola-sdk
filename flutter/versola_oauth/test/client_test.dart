import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:versola_oauth/src/messages.g.dart';
import 'package:versola_oauth/versola_oauth.dart';

/// A scripted host: records what crossed and answers from a queue. The bridge is mocked, so
/// these tests prove the Dart shape and the error categories, not the native SDKs (`testing.md`).
class FakeHost extends OAuthHostApi {
  final List<String> calls = [];
  final List<Object?> answers = [];

  T _next<T>(String call) {
    calls.add(call);
    return answers.removeAt(0) as T;
  }

  @override
  Future<VoidResult> create(
    String handle,
    ConfigurationMessage configuration,
  ) async => _next('create:$handle');
  @override
  Future<SessionStateMessage> sessionState(String handle) async =>
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
  Future<VoidResult> resumePendingAuthorization(String handle) async =>
      _next('resume');
  @override
  Future<LogoutOutcomeMessage> logout(
    String handle,
    LogoutOptionsMessage options,
  ) async => _next('logout:${options.endSession}:${options.revoke}');
  @override
  Future<AccessTokenResult> accessToken(String handle) async =>
      _next('accessToken');
  @override
  Future<VoidResult> refresh(String handle) async => _next('refresh');
  @override
  Future<IdTokenClaimsMessage?> claims(String handle) async => _next('claims');
  @override
  Future<UserInfoResult> userInfo(String handle) async => _next('userInfo');
  @override
  Future<String?> keyAttestation(String handle) async =>
      _next('keyAttestation');
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

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  test('create asks the host once per configuration and keys the client by the handle', () async {
    final host = FakeHost()..answers.addAll([VoidOk(), VoidOk()]);
    final a = await OAuthClient.create(configuration, host: host);
    final b = await OAuthClient.create(configuration, host: host);
    expect(identical(a, b), isTrue);
    expect(host.calls, hasLength(2));
    expect(host.calls.first, startsWith('create:'));
  });

  test('a configuration the native side refuses is a ConfigurationError from create', () async {
    final host = FakeHost()
      ..answers.add(
        VoidFailure(
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
      final host = FakeHost()
        ..answers.addAll([VoidOk(), VoidOk(), VoidFailure(error: reauth())]);
      final client = await OAuthClient.create(configuration, host: host);
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
      final host = FakeHost()..answers.addAll([VoidOk(), VoidOk()]);
      final client = await OAuthClient.create(configuration, host: host);
      await client.stepUp(
        const StepUpError('step-up', acrValues: ['urn:acr:mfa'], maxAge: 60),
      );
      expect(host.calls.last, 'stepUp:urn:acr:mfa:60');
    },
  );

  test('accessToken returns the token or throws the typed error, and caches nothing', () async {
    final host = FakeHost()
      ..answers.addAll([
        VoidOk(),
        AccessTokenOk(
          token: AccessTokenMessage(value: 'at-1', tokenType: 'DPoP'),
        ),
        AccessTokenOk(
          token: AccessTokenMessage(value: 'at-2', tokenType: 'DPoP'),
        ),
        AccessTokenFailure(error: reauth()),
      ]);
    final client = await OAuthClient.create(configuration, host: host);
    expect((await client.accessToken()).value, 'at-1');
    expect((await client.accessToken()).value, 'at-2');
    await expectLater(
      client.accessToken(),
      throwsA(isA<ReauthenticateError>()),
    );
    expect(host.calls.where((c) => c == 'accessToken'), hasLength(3));
  });

  test(
    'logout, claims, userInfo and keyAttestation map their answers',
    () async {
      final host = FakeHost()
        ..answers.addAll([
          VoidOk(),
          LogoutOutcomeMessage(sessionEnded: true, tokenRevoked: false),
          IdTokenClaimsMessage(
            subject: 'alice',
            issuer: 'https://id.example.com',
            audience: ['app'],
            issuedAtEpochSeconds: 1700000000,
            expiresAtEpochSeconds: 1700000300,
            acr: 'urn:acr:mfa',
            amr: ['pwd'],
            all: {'sub': 'alice'},
          ),
          null,
          UserInfoOk(
            userInfo: UserInfoMessage(
              subject: 'alice',
              claims: {'name': 'Alice'},
            ),
          ),
          'strongBox',
        ]);
      final client = await OAuthClient.create(configuration, host: host);
      final outcome = await client.logout(const LogoutOptions(revoke: false));
      expect(host.calls.last, 'logout:true:false');
      expect(outcome.sessionEnded, isTrue);
      final claims = await client.claims;
      expect(claims?.expiresAt, DateTime.utc(2023, 11, 14, 22, 18, 20));
      expect(claims?.acr, 'urn:acr:mfa');
      expect(await client.claims, isNull);
      expect((await client.userInfo()).claims['name'], 'Alice');
      expect(await client.keyAttestation(), 'strongBox');
    },
  );

  test('sessionStates maps the event channel of this client', () async {
    final host = FakeHost()..answers.add(VoidOk());
    final client = await OAuthClient.create(configuration, host: host);
    // The channel name is the Pigeon one with the handle as the instance name.
    final channelName =
        'dev.flutter.pigeon.versola_oauth.SessionStateEvents.sessionStates.${host.calls.first.substring('create:'.length)}';
    final binding =
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
    const codec = pigeonMethodCodec;
    binding.setMockStreamHandler(
      EventChannel(channelName, codec),
      MockStreamHandler.inline(
        onListen: (args, sink) {
          sink.success(SessionStateMessage.unauthenticated);
          sink.success(SessionStateMessage.authorizing);
          sink.success(SessionStateMessage.authenticated);
          sink.endOfStream();
        },
      ),
    );
    expect(await client.sessionStates().toList(), [
      SessionState.unauthenticated,
      SessionState.authorizing,
      SessionState.authenticated,
    ]);
  });
}
