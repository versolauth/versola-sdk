import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:versola_oauth/src/client.dart' show createOAuthClientWithHost;
import 'package:versola_oauth/src/mapping.dart' show toMessage;
import 'package:versola_oauth/src/messages.g.dart';
import 'package:versola_oauth/versola_oauth.dart';

import 'client_test.dart' show FakeHost, configuration, created, settle;

// Audit tests for the Flutter plugin (findings F1-F6, F9). Each asserts the CORRECT behaviour
// and is expected to fail until the finding is fixed; no production code was changed.

String channelName(String handle) =>
    'dev.flutter.pigeon.versola_oauth.SessionStateEvents.sessionStates.$handle';

TestDefaultBinaryMessenger get messenger =>
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;

/// The native side of ONE event channel, modelled as the platform does it: a channel name has
/// a single sink, a later `listen` replaces it, and a `cancel` clears it whoever sent it.
class SharedNativeChannel {
  SharedNativeChannel(this.handle) {
    messenger.setMockStreamHandler(
      EventChannel(channelName(handle), pigeonMethodCodec),
      MockStreamHandler.inline(
        onListen: (args, events) {
          listens++;
          sink = events;
        },
        onCancel: (args) {
          cancels++;
          sink = null;
        },
      ),
    );
  }
  final String handle;
  int listens = 0;
  int cancels = 0;
  MockStreamHandlerEventSink? sink;
  void emit(SessionStateMessage s) => sink?.success(s);
}

class PendingLoginHost extends FakeHost {
  final Completer<VoidResult> loginResult = Completer<VoidResult>();
  final List<String> invocations = [];
  @override
  Future<VoidResult> login(String handle, LoginOptionsMessage options) {
    invocations.add('login');
    return loginResult.future;
  }

  // The proposed host call; absent from the generated API today.
  @override
  dynamic noSuchMethod(Invocation invocation) {
    invocations.add(invocation.memberName.toString());
    return Future<VoidResult>.value(VoidOk());
  }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  group('AUDIT F1 shared native channel', () {
    test('AUDIT F1: two clients with one native handle both receive state events', () async {
      final host = FakeHost();
      final a = await created(host, handle: 'shared-1');
      final b = await created(host, handle: 'shared-1');
      final native = SharedNativeChannel('shared-1');
      final seenA = <SessionState>[];
      final seenB = <SessionState>[];
      final subA = a.sessionStates().listen(seenA.add);
      await settle();
      final subB = b.sessionStates().listen(seenB.add);
      await settle();
      native.emit(SessionStateMessage.authenticated);
      await settle();
      expect(seenA, [SessionState.authenticated], reason: 'first client went silent');
      expect(seenB, [SessionState.authenticated]);
      await subA.cancel();
      await subB.cancel();
    });

    test('AUDIT F1: cancelling one client\'s stream does not stop the other client\'s', () async {
      final host = FakeHost();
      final a = await created(host, handle: 'shared-2');
      final b = await created(host, handle: 'shared-2');
      final native = SharedNativeChannel('shared-2');
      final seenA = <SessionState>[];
      final subA = a.sessionStates().listen(seenA.add);
      await settle();
      final subB = b.sessionStates().listen((_) {});
      await settle();
      await subB.cancel();
      await settle();
      native.emit(SessionStateMessage.loggingOut);
      await settle();
      expect(seenA, [SessionState.loggingOut], reason: 'cancel on B stopped A natively');
      await subA.cancel();
    });
  });

  group('AUDIT F2 errors crossing the public API are OAuthError', () {
    test('AUDIT F2: a state index this Dart enum does not know is a typed error, not RangeError', () async {
      final client = await created(FakeHost(), handle: 'skew');
      SharedNativeChannel('skew');
      final errors = <Object>[];
      final sub = client.sessionStates().listen((_) {}, onError: errors.add);
      await settle();
      // Success envelope, enum type 129, int32 index 99: what a newer native side would send.
      final bytes = ByteData(7)
        ..setUint8(0, 0)
        ..setUint8(1, 129)
        ..setUint8(2, 3)
        ..setInt32(3, 99, Endian.little);
      await messenger.handlePlatformMessage(channelName('skew'), bytes, (_) {});
      await settle();
      expect(errors, hasLength(1));
      expect(errors.single, isA<OAuthError>());
      await sub.cancel();
    });

    test('AUDIT F2: a raw PlatformException on the event stream arrives as an OAuthError', () async {
      final client = await created(FakeHost(), handle: 'pe');
      final native = SharedNativeChannel('pe');
      final errors = <Object>[];
      final sub = client.sessionStates().listen((_) {}, onError: errors.add);
      await settle();
      native.sink!.error(code: 'boom', message: 'native text', details: null);
      await settle();
      expect(errors, hasLength(1));
      expect(errors.single, isA<OAuthError>(), reason: 'got ${errors.single.runtimeType}');
      await sub.cancel();
    });
  });

  group('AUDIT F3 unsupported platforms', () {
    tearDown(() => debugDefaultTargetPlatformOverride = null);

    test('AUDIT F3: create on Linux is a clear UnsupportedError, not a channel-error ConfigurationError', () async {
      debugDefaultTargetPlatformOverride = TargetPlatform.linux;
      // No host injected and no mock handler: what an app without a registered plugin sees.
      await expectLater(
        OAuthClient.create(configuration),
        throwsA(
          isA<UnsupportedError>().having(
            (e) => e.message,
            'message',
            contains('Android and iOS only'),
          ),
        ),
      );
    });
    // kIsWeb is a compile-time constant: the web branch needs `flutter test --platform chrome`.
  });

  group('AUDIT F5 stream end', () {
    test('AUDIT F5: sessionStates completes when the native stream ends', () async {
      final client = await created(FakeHost(), handle: 'done');
      final native = SharedNativeChannel('done');
      final done = Completer<void>();
      final sub = client.sessionStates().listen((_) {}, onDone: done.complete);
      await settle();
      native.sink!.endOfStream();
      await settle();
      expect(
        done.isCompleted,
        isTrue,
        reason: 'the consumer never saw done',
      );
      await sub.cancel();
    });
  });

  group('AUDIT F6 value semantics', () {
    // Built at run time with `new`-style non-const calls: const instances are canonicalised and
    // would be `identical`, which proves nothing about ==.
    String v(String x) => String.fromCharCodes(x.codeUnits);

    void expectValueEqual(Object Function() make, String name) {
      final x = make();
      final y = make();
      expect(identical(x, y), isFalse);
      expect(x, y, reason: '$name has no ==');
      expect(x.hashCode, y.hashCode, reason: '$name has no hashCode');
    }

    test('AUDIT F6: AccessToken is equal by value', () {
      expectValueEqual(() => AccessToken(value: v('a'), tokenType: v('Bearer')), 'AccessToken');
    });
    test('AUDIT F6: LogoutOutcome is equal by value', () {
      expectValueEqual(() => LogoutOutcome(sessionEnded: true, tokenRevoked: false), 'LogoutOutcome');
    });
    test('AUDIT F6: LoginOptions is equal by value', () {
      expectValueEqual(() => LoginOptions(loginHint: v('x'), uiLocales: [v('en')]), 'LoginOptions');
    });
    test('AUDIT F6: OAuthConfiguration is equal by value', () {
      expectValueEqual(
        () => OAuthConfiguration(
          issuer: v('https://i.example.com'),
          clientId: v('c'),
          redirectUri: v('https://a.example.com/cb'),
          scopes: {v('openid')},
        ),
        'OAuthConfiguration',
      );
    });
    test('AUDIT F6: IdTokenClaims is equal by value', () {
      final t = DateTime.utc(2030);
      expectValueEqual(
        () => IdTokenClaims(subject: v('s'), issuer: v('i'), audience: [v('a')], issuedAt: t, expiresAt: t),
        'IdTokenClaims',
      );
    });
    test('AUDIT F6: OAuthError subtypes are equal by value', () {
      expectValueEqual(
        () => ConfigurationError(ConfigurationDetail.invalidConfiguration, v('m'), text: v('t')),
        'ConfigurationError',
      );
    });

    test('AUDIT F6: a set mutated after construction does not change the configuration', () {
      final scopes = <String>{'openid'};
      final origins = <String>{'https://api.example.com'};
      final c = OAuthConfiguration(
        clientId: 'c',
        redirectUri: 'https://a.example.com/cb',
        scopes: scopes,
        protectedOrigins: origins,
      );
      scopes.add('admin');
      origins.add('https://evil.example.com');
      expect(c.scopes, {'openid'});
      expect(c.protectedOrigins, {'https://api.example.com'});
      expect(() => c.scopes.add('x'), throwsUnsupportedError, reason: 'exposed set is mutable');
    });

    test('AUDIT F6: a list mutated after construction does not change LoginOptions', () {
      final locales = <String>['en'];
      final o = LoginOptions(uiLocales: locales);
      locales.add('de');
      expect(o.uiLocales, ['en']);
    });

    test('AUDIT F6: a sub-second clockSkewTolerance is rejected, not truncated to whole seconds', () async {
      final host = FakeHost()..answers.add(CreateOk(handle: 'h'));
      await expectLater(
        () async => createOAuthClientWithHost(
          OAuthConfiguration(
            clientId: 'c',
            redirectUri: 'https://a.example.com/cb',
            clockSkewTolerance: const Duration(milliseconds: 1500),
          ),
          host,
        ),
        throwsArgumentError,
      );
    });

    test('AUDIT F6: a sub-millisecond retry backoff is rejected, not truncated to 0 ms', () {
      expect(
        () => toMessage(
          OAuthConfiguration(
            clientId: 'c',
            redirectUri: 'https://a.example.com/cb',
            retryPolicy: const RetryPolicy(initialBackoff: Duration(microseconds: 400)),
          ),
        ),
        throwsArgumentError,
      );
    });
  });

  group('AUDIT F9 cancel from Dart', () {
    // Design test: `cancelLogin()` is the proposed name. Called dynamically so the file compiles
    // before the API exists (today it fails with NoSuchMethodError).
    test('AUDIT F9: cancelLogin() on an in-flight login reaches the host', () async {
      final host = PendingLoginHost();
      final client = await created(host);
      final login = client.login();
      await settle();
      await (client as dynamic).cancelLogin();
      expect(host.invocations.any((i) => i.contains('cancelLogin')), isTrue);
      host.loginResult.complete(VoidOk());
      await login;
    });
  });
}
