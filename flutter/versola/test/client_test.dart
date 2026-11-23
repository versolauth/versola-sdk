import 'package:flutter/foundation.dart'
    show TargetPlatform, debugDefaultTargetPlatformOverride;
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:versola/src/messages.g.dart';
import 'package:versola/src/native_client.dart';
import 'package:versola/versola.dart';

/// A scripted host: records what crossed and answers from a queue (an Exception in the queue is
/// thrown, as a channel failure would be). The bridge is mocked, so these tests prove the Dart
/// shape and the error categories, not the native SDKs (`testing.md`).
class FakeHost extends VersolaHostApi {
  final List<String> calls = [];
  final List<Object?> answers = [];

  /// What crossed, in order, for the tests that assert on the messages themselves.
  final List<VersolaConfigurationMessage> configurations = [];
  final List<VersolaLoginOptionsMessage> loginOptions = [];
  final List<VersolaLoginOptionsMessage?> stepUpOptions = [];
  final List<VersolaHttpRequestMessage> requests = [];

  T _next<T>(String call) {
    calls.add(call);
    final answer = answers.removeAt(0);
    if (answer is Exception) throw answer;
    return answer as T;
  }

  @override
  Future<VersolaCreateResult> create(
    VersolaConfigurationMessage configuration,
  ) async {
    configurations.add(configuration);
    return _next('create:${configuration.clientId}');
  }

  @override
  Future<VersolaSessionStateResult> sessionState(String handle) async =>
      _next('sessionState');

  @override
  Future<VersolaVoidResult> login(
    String handle,
    VersolaLoginOptionsMessage options,
  ) async {
    loginOptions.add(options);
    return _next('login:${options.prompt?.name}');
  }

  @override
  Future<VersolaVoidResult> stepUp(
    String handle,
    List<String> acrValues,
    int? maxAge,
    VersolaLoginOptionsMessage? options,
  ) async {
    stepUpOptions.add(options);
    return _next('stepUp:${acrValues.join(",")}:$maxAge');
  }

  @override
  Future<VersolaLogoutResult> logout(
    String handle,
    VersolaLogoutOptionsMessage options,
  ) async => _next('logout:${options.endSession}:${options.revoke}');

  @override
  Future<VersolaVoidResult> refresh(String handle) async => _next('refresh');

  @override
  Future<VersolaClaimsResult> claims(String handle) async => _next('claims');

  @override
  Future<VersolaKeyAttestationResult> keyAttestation(String handle) async =>
      _next('keyAttestation');

  @override
  Future<VersolaHttpResult> httpRequest(
    String handle,
    VersolaHttpRequestMessage request,
  ) async {
    requests.add(request);
    return _next('httpRequest');
  }
}

const configuration = VersolaConfiguration(
  edgeUrl: 'https://id.example.com',
  clientId: 'app',
  redirectUri: 'https://app.example.com/oauth',
);

VersolaErrorMessage reauth() => VersolaErrorMessage(
  category: VersolaErrorCategoryMessage.reauthenticate,
  kind: 'grantRejected',
  message: 'reauthenticate: GrantRejected',
);

Future<Versola> created(
  FakeHost host, {
  String handle = 'h1',
  VersolaConfiguration config = configuration,
}) async {
  host.answers.insert(0, VersolaCreateOk(handle: handle));
  return createVersolaWithHost(config, host);
}

/// The event channel the generated `sessionStates` opens for [handle], with the native side
/// scripted: `sink` is the native sink once somebody listens, the counters say how often.
class NativeStates {
  NativeStates(String handle) {
    final channel = EventChannel(
      'dev.flutter.pigeon.versola.VersolaSessionStateEvents.sessionStates.$handle',
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
  void emit(VersolaSessionStateMessage state) => sink!.success(state);
}

Future<void> settle() => Future<void>.delayed(Duration.zero);

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  group('create', () {
    test('the configuration reaches the host message field for field, with issuer null when not given', () async {
      final host = FakeHost();
      await created(host);
      final sent = host.configurations.single;
      expect(sent.edgeUrl, 'https://id.example.com');
      expect(sent.clientId, 'app');
      expect(sent.redirectUri, 'https://app.example.com/oauth');
      expect(sent.issuer, isNull, reason: 'native defaults it to edgeUrl');
      expect(sent.postLogoutRedirectUri, isNull);
      expect(sent.requireHardwareKey, isFalse);
      expect(sent.unlockPolicy, VersolaUnlockPolicyMessage.none);
      expect(sent.clockSkewToleranceSeconds, 60);
      expect(sent.retryPolicy, isNull, reason: 'native default policy');
    });

    test('every configured field crosses, the issuer as written and the retry policy whole', () async {
      final host = FakeHost();
      await created(
        host,
        config: const VersolaConfiguration(
          edgeUrl: 'https://edge.partner.example.com',
          clientId: 'partner-app',
          redirectUri: 'https://app.example.com/cb',
          issuer: 'https://id.example.com/',
          postLogoutRedirectUri: 'https://app.example.com/out',
          requireHardwareKey: true,
          unlockPolicy: UnlockPolicy.onAppUnlock,
          clockSkewTolerance: Duration(seconds: 120),
          retryPolicy: RetryPolicy(
            maxAttemptsPerOrigin: 2,
            maxTotalAttempts: 3,
            initialBackoff: Duration(milliseconds: 250),
            backoffMultiplier: 1.5,
            maxBackoff: Duration(seconds: 4),
            totalBudget: Duration(seconds: 10),
          ),
        ),
      );
      final sent = host.configurations.single;
      expect(sent.edgeUrl, 'https://edge.partner.example.com');
      expect(sent.clientId, 'partner-app');
      expect(sent.redirectUri, 'https://app.example.com/cb');
      expect(
        sent.issuer,
        'https://id.example.com/',
        reason: 'a trailing slash is the app\'s, kept byte for byte',
      );
      expect(sent.postLogoutRedirectUri, 'https://app.example.com/out');
      expect(sent.requireHardwareKey, isTrue);
      expect(sent.unlockPolicy, VersolaUnlockPolicyMessage.onAppUnlock);
      expect(sent.clockSkewToleranceSeconds, 120);
      final retry = sent.retryPolicy!;
      expect(retry.maxAttemptsPerOrigin, 2);
      expect(retry.maxTotalAttempts, 3);
      expect(retry.initialBackoffMillis, 250);
      expect(retry.backoffMultiplier, 1.5);
      expect(retry.maxBackoffMillis, 4000);
      expect(retry.totalBudgetMillis, 10000);
    });

    test('the client keeps the configuration it was created with', () async {
      final client = await created(FakeHost(), handle: 'client-7');
      expect(client.configuration, configuration);
    });

    test('a configuration the native side refuses is a ConfigurationError from create', () async {
      final host = FakeHost()
        ..answers.add(
          VersolaCreateFailure(
            error: VersolaErrorMessage(
              category: VersolaErrorCategoryMessage.configuration,
              kind: 'invalidConfiguration',
              message: 'configuration: bad',
              detail: 'edgeUrl must be an origin',
            ),
          ),
        );
      await expectLater(
        createVersolaWithHost(
          const VersolaConfiguration(
            edgeUrl: 'https://id.example.com/path',
            clientId: 'app',
            redirectUri: 'https://app.example.com/oauth',
          ),
          host,
        ),
        throwsA(
          isA<ConfigurationError>()
              .having(
                (e) => e.detail,
                'detail',
                ConfigurationDetail.invalidConfiguration,
              )
              .having((e) => e.text, 'text', 'edgeUrl must be an origin'),
        ),
      );
    });

    test('a sub-second clockSkewTolerance is rejected before any native call, not truncated', () async {
      final host = FakeHost();
      await expectLater(
        createVersolaWithHost(
          const VersolaConfiguration(
            edgeUrl: 'https://id.example.com',
            clientId: 'app',
            redirectUri: 'https://app.example.com/oauth',
            clockSkewTolerance: Duration(milliseconds: 1500),
          ),
          host,
        ),
        throwsArgumentError,
      );
      expect(host.calls, isEmpty);
    });

    test(
      'a sub-millisecond retry backoff is rejected before any native call',
      () async {
        final host = FakeHost();
        await expectLater(
          createVersolaWithHost(
            const VersolaConfiguration(
              edgeUrl: 'https://id.example.com',
              clientId: 'app',
              redirectUri: 'https://app.example.com/oauth',
              retryPolicy: RetryPolicy(
                initialBackoff: Duration(microseconds: 400),
              ),
            ),
            host,
          ),
          throwsArgumentError,
        );
        expect(host.calls, isEmpty);
      },
    );

    test('create on an unsupported platform is an UnsupportedError', () async {
      debugDefaultTargetPlatformOverride = TargetPlatform.linux;
      addTearDown(() => debugDefaultTargetPlatformOverride = null);
      await expectLater(
        Versola.create(configuration),
        throwsA(isA<UnsupportedError>()),
      );
    });
  });

  group('login', () {
    test('every option reaches the host message untouched, the JSON strings included', () async {
      final host = FakeHost();
      final client = await created(host);
      host.answers.add(VersolaVoidOk());
      const claims = '{"id_token":{"email":{"essential":true}}}';
      const details = '[{"type":"payment","actions":["initiate"]}]';
      await client.login(
        LoginOptions(
          scopes: {'profile', 'email'},
          acrValues: ['sensitive', 'urn:acr:mfa'],
          maxAge: 300,
          prompt: Prompt.selectAccount,
          loginHint: 'alice@example.com',
          uiLocales: ['de', 'en'],
          resources: ['https://api.example.com', 'https://other.example.com'],
          claims: claims,
          authorizationDetails: details,
          ephemeralBrowser: true,
        ),
      );
      final sent = host.loginOptions.single;
      expect(sent.scopes.toSet(), {'profile', 'email'});
      expect(sent.acrValues, ['sensitive', 'urn:acr:mfa']);
      expect(sent.maxAge, 300);
      expect(sent.prompt, VersolaPromptMessage.selectAccount);
      expect(sent.loginHint, 'alice@example.com');
      expect(sent.uiLocales, ['de', 'en']);
      expect(sent.resources, [
        'https://api.example.com',
        'https://other.example.com',
      ]);
      expect(sent.claims, same(claims));
      expect(sent.authorizationDetails, same(details));
      expect(sent.ephemeralBrowser, isTrue);
    });

    test(
      'login without options sends the native defaults, not a guessed value',
      () async {
        final host = FakeHost();
        final client = await created(host);
        host.answers.add(VersolaVoidOk());
        await client.login();
        final sent = host.loginOptions.single;
        expect(sent.scopes, isEmpty);
        expect(sent.acrValues, isEmpty);
        expect(sent.maxAge, isNull);
        expect(sent.prompt, isNull);
        expect(sent.claims, isNull);
        expect(sent.authorizationDetails, isNull);
        expect(sent.ephemeralBrowser, isFalse);
      },
    );

    test('a failure arrives as its category', () async {
      final host = FakeHost();
      final client = await created(host);
      host.answers.addAll([
        VersolaVoidOk(),
        VersolaVoidFailure(error: reauth()),
      ]);
      await client.login(LoginOptions(prompt: Prompt.login));
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
    });

    test('the edge_client_unknown case arrives as the unknown detail, named, with its stable code', () async {
      final host = FakeHost();
      final client = await created(host);
      host.answers.add(
        VersolaVoidFailure(
          error: VersolaErrorMessage(
            category: VersolaErrorCategoryMessage.configuration,
            kind: 'unknown',
            message: 'configuration: edge_client_unknown',
            detail: 'edge_client_unknown',
            sdkCode: 'configuration.edge_client_unknown',
          ),
        ),
      );
      await expectLater(
        client.login(),
        throwsA(
          isA<ConfigurationError>()
              .having((e) => e.detail, 'detail', ConfigurationDetail.unknown)
              .having((e) => e.text, 'text', 'edge_client_unknown')
              .having(
                (e) => e.sdkCode,
                'sdkCode',
                'configuration.edge_client_unknown',
              ),
        ),
      );
    });
  });

  group('stepUp', () {
    test('without options the host is told there are none, which is not an empty LoginOptions', () async {
      final host = FakeHost();
      final client = await created(host);
      host.answers.add(VersolaVoidOk());
      await client.stepUp(
        const StepUpError('step-up', acrValues: ['urn:acr:mfa'], maxAge: 60),
      );
      expect(host.calls.last, 'stepUp:urn:acr:mfa:60');
      expect(host.stepUpOptions.single, isNull);
    });

    test('with options the host gets them, and the challenge still comes from the error', () async {
      final host = FakeHost();
      final client = await created(host);
      host.answers.add(VersolaVoidOk());
      await client.stepUp(
        const StepUpError('step-up', acrValues: ['sensitive'], maxAge: 0),
        LoginOptions(scopes: {'profile'}, ephemeralBrowser: true),
      );
      expect(host.calls.last, 'stepUp:sensitive:0');
      final sent = host.stepUpOptions.single!;
      expect(sent.scopes, ['profile']);
      expect(sent.ephemeralBrowser, isTrue);
    });

    test('the account-mismatch refusal is the Recoverable cause, with its stable code', () async {
      final host = FakeHost();
      final client = await created(host);
      host.answers.add(
        VersolaVoidFailure(
          error: VersolaErrorMessage(
            category: VersolaErrorCategoryMessage.recoverable,
            kind: 'accountMismatch',
            message: 'recoverable: AccountMismatch',
            sdkCode: 'recoverable.account_mismatch',
          ),
        ),
      );
      await expectLater(
        client.stepUp(const StepUpError('s', acrValues: ['sensitive'])),
        throwsA(
          isA<RecoverableError>()
              .having((e) => e.cause, 'cause', RecoverableCause.accountMismatch)
              .having(
                (e) => e.sdkCode,
                'sdkCode',
                'recoverable.account_mismatch',
              ),
        ),
      );
    });
  });

  test('logout, claims, sessionState, refresh and keyAttestation map their answers', () async {
    final host = FakeHost();
    final client = await created(host);
    host.answers.addAll([
      VersolaLogoutOk(
        outcome: VersolaLogoutOutcomeMessage(
          sessionEnded: true,
          tokenRevoked: false,
        ),
      ),
      VersolaClaimsOk(
        claims: VersolaIdTokenClaimsMessage(
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
      VersolaClaimsOk(),
      VersolaSessionStateOk(state: VersolaSessionStateMessage.authenticated),
      VersolaVoidOk(),
      VersolaKeyAttestationOk(tier: 'strongBox'),
      VersolaKeyAttestationOk(),
    ]);
    final outcome = await client.logout(const LogoutOptions(revoke: false));
    expect(host.calls.last, 'logout:true:false');
    expect(outcome.sessionEnded, isTrue);
    expect(outcome.tokenRevoked, isFalse);
    final claims = await client.claims();
    expect(claims?.expiresAt, DateTime.utc(2023, 11, 14, 22, 18, 20));
    expect(claims?.acr, 'urn:acr:mfa');
    expect(await client.claims(), isNull);
    expect(await client.currentSessionState(), SessionState.authenticated);
    await client.refresh();
    expect(host.calls.last, 'refresh');
    expect(await client.keyAttestation(), 'strongBox');
    expect(await client.keyAttestation(), isNull);
  });

  test('keyAttestation without hardware is a ConfigurationError, not a PlatformException', () async {
    final host = FakeHost();
    final client = await created(host);
    host.answers.add(
      VersolaKeyAttestationFailure(
        error: VersolaErrorMessage(
          category: VersolaErrorCategoryMessage.configuration,
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
      client.keyAttestation,
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
      createVersolaWithHost(configuration, host),
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
        ..emit(VersolaSessionStateMessage.unauthenticated)
        ..emit(VersolaSessionStateMessage.authorizing)
        ..emit(VersolaSessionStateMessage.authenticated);
      await settle();
      expect(seen, [
        SessionState.unauthenticated,
        SessionState.authorizing,
        SessionState.authenticated,
      ]);
      await sub.cancel();
    });

    test('two listeners both see every state and share one native subscription; a late one gets the latest first', () async {
      final client = await created(FakeHost(), handle: 'h-two');
      final native = NativeStates('h-two');
      final a = <SessionState>[];
      final b = <SessionState>[];
      final subA = client.sessionStates().listen(a.add);
      await settle();
      native.emit(VersolaSessionStateMessage.unauthenticated);
      await settle();
      // A second listener joins late: it is told the latest state, then every change.
      final subB = client.sessionStates().listen(b.add);
      await settle();
      native.emit(VersolaSessionStateMessage.authenticated);
      await settle();
      expect(a, [SessionState.unauthenticated, SessionState.authenticated]);
      expect(b, [SessionState.unauthenticated, SessionState.authenticated]);
      expect(native.listens, 1);

      // One cancelling leaves the other running, and the native collection alive.
      await subB.cancel();
      await settle();
      expect(native.cancels, 0);
      native.emit(VersolaSessionStateMessage.loggingOut);
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
      native.emit(VersolaSessionStateMessage.unauthenticated);
      await settle();
      expect(c, [SessionState.unauthenticated]);
      await subC.cancel();
    });

    test('two clients with one handle share the native subscription, and one cancelling does not stop the other', () async {
      final first = await created(FakeHost(), handle: 'h-shared');
      final second = await created(FakeHost(), handle: 'h-shared');
      final native = NativeStates('h-shared');
      final a = <SessionState>[];
      final b = <SessionState>[];
      final subA = first.sessionStates().listen(a.add);
      final subB = second.sessionStates().listen(b.add);
      await settle();
      expect(native.listens, 1);
      await subA.cancel();
      await settle();
      native.emit(VersolaSessionStateMessage.authenticated);
      await settle();
      expect(b, [SessionState.authenticated]);
      await subB.cancel();
    });

    test('a native event that cannot be decoded arrives as an OAuthError on the stream, with none of the native text', () async {
      final client = await created(FakeHost(), handle: 'h-unknown');
      final channel = EventChannel(
        'dev.flutter.pigeon.versola.VersolaSessionStateEvents.sessionStates.h-unknown',
        pigeonMethodCodec,
      );
      MockStreamHandlerEventSink? sink;
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockStreamHandler(
            channel,
            MockStreamHandler.inline(onListen: (args, events) => sink = events),
          );
      final errors = <Object>[];
      final sub = client.sessionStates().listen((_) {}, onError: errors.add);
      await settle();
      sink!.error(code: 'undecodable-event', message: 'native text');
      await settle();
      expect(errors.single, isA<ConfigurationError>());
      expect(errors.single.toString(), isNot(contains('native text')));
      await sub.cancel();
    });
  });
}
