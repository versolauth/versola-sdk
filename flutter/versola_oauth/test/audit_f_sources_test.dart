import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

// SOURCE-SCAN audit tests (F4, F7, F8, F11): they read repository files as text, not behaviour.
// Each asserts the CORRECT state and is expected to fail until the finding is fixed.

String read(String path) => File(path).readAsStringSync();

void main() {
  test('AUDIT F4: no public signature mentions a generated Pigeon type (OAuthHostApi)', () {
    final entry = read('lib/versola_oauth.dart');
    final exported = RegExp(r"export 'src/([a-z_]+)\.dart'")
        .allMatches(entry)
        .map((m) => m.group(1)!)
        .where((n) => n != 'messages.g')
        .toList();
    expect(exported, isNotEmpty);
    for (final name in exported) {
      final src = read('lib/src/$name.dart');
      // Public API = everything outside private members; the scan is deliberately coarse:
      // any mention of a bridge type outside a line starting with `_`-private declarations.
      final leaks = src
          .split('\n')
          .where((l) => !l.trimLeft().startsWith('//'))
          .where((l) => RegExp(r'bridge\.\w+Api|OAuthHostApi').hasMatch(l))
          .where(
            (l) => !RegExp(r'(final|late final)\s+bridge\.\w+\s+_').hasMatch(l),
          )
          .where((l) => !l.contains('host ??')) // method body, not signature
          .toList();
      expect(leaks, isEmpty, reason: 'lib/src/$name.dart exposes: $leaks');
    }
  });

  test(
    'AUDIT F7: pubspec environment has no upper bound below the next major',
    () {
      final pubspec = read('pubspec.yaml');
      final sdk = RegExp(
        r'^\s+sdk:\s*"([^"]+)"',
        multiLine: true,
      ).firstMatch(pubspec)!.group(1)!;
      final flutter = RegExp(
        r'^\s+flutter:\s*"([^"]+)"',
        multiLine: true,
      ).firstMatch(pubspec)!.group(1)!;
      int? upperMajor(String c) {
        final m = RegExp(r'<\s*(\d+)\.(\d+)\.(\d+)').firstMatch(c);
        if (m == null) return null; // no upper bound
        // The smallest major a constraint with this upper bound still excludes: `<3.14.0` cuts
        // off 3.x, `<4.0.0` is the next-major cap.
        return m.group(2) == '0' && m.group(3) == '0'
            ? int.parse(m.group(1)!)
            : int.parse(m.group(1)!) - 1;
      }

      final sdkUpper = upperMajor(sdk);
      final flutterUpper = upperMajor(flutter);
      expect(
        sdkUpper == null || sdkUpper >= 4,
        isTrue,
        reason: 'sdk "$sdk" caps below Dart 4',
      );
      expect(
        flutterUpper == null || flutterUpper >= 4,
        isTrue,
        reason: 'flutter "$flutter" caps below Flutter 4',
      );
    },
  );

  test('AUDIT F7: README http range equals the pubspec http range', () {
    final pubspec = read('pubspec.yaml');
    final pub = RegExp(
      r'^\s+http:\s*"([^"]+)"',
      multiLine: true,
    ).firstMatch(pubspec)!.group(1)!;
    final readme = read('README.md');
    final doc = RegExp(r'`http`\s*\(`([^`]+)`\)').firstMatch(readme)?.group(1);
    expect(doc, isNotNull, reason: 'README does not state an http range');
    expect(doc, pub);
  });

  test('AUDIT F8: an abstract interface exists in the exported API for apps to fake', () {
    final entry = read('lib/versola_oauth.dart');
    final exported = RegExp(r"export 'src/([a-z_]+)\.dart'")
        .allMatches(entry)
        .map((m) => m.group(1)!);
    final found = exported.any(
      (n) =>
          RegExp(r'abstract interface class \w+')
              .hasMatch(read('lib/src/$n.dart')),
    );
    expect(
      found,
      isTrue,
      reason:
          'OAuthClient is a final class and no abstract interface is exported',
    );
  });

  test(
    'AUDIT F11: README quickstart covers the platform setup an app needs',
    () {
      final readme = read('README.md');
      expect(
        readme.contains('VersolaRedirectActivity'),
        isTrue,
        reason: 'Android manifest redirect activity',
      );
      expect(
        readme.contains('Associated Domains'),
        isTrue,
        reason: 'iOS entitlement',
      );
      expect(
        readme.contains('ensureInitialized'),
        isTrue,
        reason: 'WidgetsFlutterBinding.ensureInitialized()',
      );
      expect(
        readme.contains('enable-swift-package-manager'),
        isTrue,
        reason: 'flutter config command',
      );
    },
  );
}
