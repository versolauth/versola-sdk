import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:versola/versola.dart';

import 'client_test.dart' show FakeHost, created;

String read(String path) => File(path).readAsStringSync();

String withoutComments(String source) =>
    source.split('\n').where((l) => !l.trimLeft().startsWith('//')).join('\n');

/// A fake an app would write. It implements exactly the interface's members: if `VersolaApi`
/// gained `accessToken()` (or any other abstract member) this class would stop compiling, which
/// is the surface check that a test of strings cannot give.
class AppFake implements VersolaApi {
  @override
  Stream<SessionState> sessionStates() => const Stream.empty();
  @override
  Future<SessionState> currentSessionState() async =>
      SessionState.unauthenticated;
  @override
  Future<IdTokenClaims?> claims() async => null;
  @override
  Future<void> login([LoginOptions? options]) async {}
  @override
  Future<void> stepUp(StepUpError challenge, [LoginOptions? options]) async {}
  @override
  Future<LogoutOutcome> logout([
    LogoutOptions options = const LogoutOptions(),
  ]) async => const LogoutOutcome(sessionEnded: false, tokenRevoked: false);
  @override
  Future<void> refresh() async {}
  @override
  Future<String?> keyAttestation() async => null;
}

void main() {
  test('the API an app can fake has no accessToken, userInfo or metadata, and Versola implements it', () async {
    expect(AppFake(), isA<VersolaApi>());
    final client = await created(FakeHost());
    expect(client, isA<VersolaApi>());

    for (final file in ['lib/src/api.dart', 'lib/src/client.dart']) {
      final src = withoutComments(read(file));
      for (final forbidden in ['accessToken', 'userInfo', 'metadata']) {
        expect(
          RegExp('\\b$forbidden\\b').hasMatch(src),
          isFalse,
          reason: '$file declares $forbidden',
        );
      }
    }
    // The dynamic view: asking the client for one is a NoSuchMethodError, not a token.
    // ignore: avoid_dynamic_calls
    expect(() => (client as dynamic).accessToken(), throwsNoSuchMethodError);
  });

  test('httpClient takes no origins: the scope is the edge origin and cannot be widened', () {
    final src = withoutComments(read('lib/src/client.dart'));
    expect(src, contains('http.Client httpClient();'));
    expect(RegExp(r'\borigins\b').hasMatch(src), isFalse);
    expect(
      RegExp(r'\borigins\b')
          .hasMatch(withoutComments(read('pigeons/messages.dart'))),
      isFalse,
    );
  });

  test('nothing credential-shaped is declared in the Pigeon contract', () {
    final contract = withoutComments(read('pigeons/messages.dart'));
    for (final word in [
      'accesstoken',
      'refreshtoken',
      'userinfo',
      'privatekey',
      'dpopproof',
      'verifier',
      'rawidtoken',
    ]) {
      expect(
        contract.toLowerCase().contains(word),
        isFalse,
        reason: 'contract mentions $word',
      );
    }
    // `idTokenRejection` is the name of a rejection reason; a field holding the token is not.
    expect(RegExp(r'\bidToken\b').hasMatch(contract), isFalse);
  });

  test('the entry point re-exports the shared types by name, never a blanket export or a generated file', () {
    final entry = withoutComments(read('lib/versola.dart'));
    final exports = RegExp(r"export '([^']+)'([^;]*);").allMatches(entry);
    expect(exports, isNotEmpty);
    for (final m in exports) {
      expect(m.group(2), contains('show'), reason: '${m.group(1)} has no show');
      expect(m.group(1), isNot(contains('messages.g')));
    }
    // Types of the generic facade that this one does not have stay out.
    for (final absent in [
      'AccessToken',
      'UserInfo',
      'OAuthConfiguration',
      'TokenBinding',
    ]) {
      expect(RegExp('\\b$absent\\b').hasMatch(entry), isFalse, reason: absent);
    }
  });

  test('no public signature mentions a generated Pigeon type', () {
    final entry = read('lib/versola.dart');
    final exported = RegExp(r"export 'src/([a-z_]+)\.dart'")
        .allMatches(entry)
        .map((m) => m.group(1)!)
        .toList();
    expect(exported, isNotEmpty);
    for (final name in exported) {
      final leaks = withoutComments(read('lib/src/$name.dart'))
          .split('\n')
          .where((l) => RegExp(r'bridge\.\w+|VersolaHostApi').hasMatch(l))
          .toList();
      expect(leaks, isEmpty, reason: 'lib/src/$name.dart exposes: $leaks');
    }
  });

  test('the generated channels cannot collide with versola_oauth\'s', () {
    final ours = read('lib/src/messages.g.dart');
    final theirs = read('../versola_oauth/lib/src/messages.g.dart');
    Set<String> channels(String src) =>
        RegExp(r"'(dev\.flutter\.pigeon\.[A-Za-z_.]+)")
            .allMatches(src)
            .map((m) => m.group(1)!)
            .toSet();
    final a = channels(ours);
    final b = channels(theirs);
    expect(a, isNotEmpty);
    expect(b, isNotEmpty);
    expect(a.intersection(b), isEmpty);
    expect(a.every((c) => c.startsWith('dev.flutter.pigeon.versola.')), isTrue);
  });
}
