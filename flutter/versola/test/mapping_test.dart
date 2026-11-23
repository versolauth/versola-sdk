import 'package:flutter_test/flutter_test.dart';
import 'package:versola/src/mapping.dart';
import 'package:versola/src/messages.g.dart';
import 'package:versola/versola.dart';

VersolaErrorMessage msg(
  VersolaErrorCategoryMessage category,
  String kind, {
  String? code,
  String? detail,
  String? sdkCode,
  int? status,
  int? retryAfterMillis,
  int? attempts,
  int? elapsedMillis,
  String? origin,
  String? expected,
  String? received,
  String? field,
  String? capability,
  String? idTokenRejection,
  String? errorDescription,
  List<String>? acrValues,
  int? maxAge,
}) => VersolaErrorMessage(
  category: category,
  kind: kind,
  message: 'message',
  code: code,
  detail: detail,
  sdkCode: sdkCode,
  status: status,
  retryAfterMillis: retryAfterMillis,
  attempts: attempts,
  elapsedMillis: elapsedMillis,
  origin: origin,
  expected: expected,
  received: received,
  field: field,
  capability: capability,
  idTokenRejection: idTokenRejection,
  errorDescription: errorDescription,
  acrValues: acrValues,
  maxAge: maxAge,
);

const recoverable = VersolaErrorCategoryMessage.recoverable;
const reauthenticate = VersolaErrorCategoryMessage.reauthenticate;
const configuration = VersolaErrorCategoryMessage.configuration;

void main() {
  group('errorFromMessage', () {
    test('every Recoverable cause keeps its category and payload', () {
      for (final cause in RecoverableCause.values) {
        if (cause == RecoverableCause.unknown) continue;
        final e = errorFromMessage(msg(recoverable, cause.name));
        expect(e, isA<RecoverableError>());
        expect((e as RecoverableError).cause, cause);
      }
      final server = errorFromMessage(
        msg(
          recoverable,
          'server',
          status: 429,
          retryAfterMillis: 30000,
          attempts: 1,
          elapsedMillis: 40,
          sdkCode: 'recoverable.server',
        ),
      ) as RecoverableError;
      expect(server.status, 429);
      expect(server.retryAfter, const Duration(seconds: 30));
      expect(server.attempts, 1);
      expect(server.elapsed, const Duration(milliseconds: 40));
      final noRetryAfter = errorFromMessage(
        msg(recoverable, 'server', status: 500),
      ) as RecoverableError;
      expect(noRetryAfter.retryAfter, isNull, reason: 'none is not zero');
    });

    test('accountMismatch is its own cause with the stable code', () {
      final e = errorFromMessage(
        msg(
          recoverable,
          'accountMismatch',
          sdkCode: 'recoverable.account_mismatch',
        ),
      ) as RecoverableError;
      expect(e.cause, RecoverableCause.accountMismatch);
      expect(e.sdkCode, 'recoverable.account_mismatch');
    });

    test('every Reauthenticate reason keeps its category', () {
      for (final reason in ReauthenticateReason.values) {
        if (reason == ReauthenticateReason.unknown) continue;
        final e = errorFromMessage(msg(reauthenticate, reason.name));
        expect((e as ReauthenticateError).reason, reason);
      }
      final interaction = errorFromMessage(
        msg(reauthenticate, 'interactionRequired', code: 'login_required'),
      ) as ReauthenticateError;
      expect(interaction.code, 'login_required');
    });

    test('a step-up carries its challenge', () {
      final e = errorFromMessage(
        msg(
          VersolaErrorCategoryMessage.stepUp,
          'stepUp',
          acrValues: ['sensitive'],
          maxAge: 300,
        ),
      ) as StepUpError;
      expect(e.acrValues, ['sensitive']);
      expect(e.maxAge, 300);
      expect(e.sdkCode, 'step_up');
    });

    test('every Configuration detail keeps its category and payload', () {
      for (final detail in ConfigurationDetail.values) {
        if (detail == ConfigurationDetail.unknown) continue;
        final e = errorFromMessage(msg(configuration, detail.name));
        expect((e as ConfigurationError).detail, detail);
      }
      final issuer = errorFromMessage(
        msg(
          configuration,
          'issuerMismatch',
          expected: 'https://id.example.com',
          received: 'https://evil.example.com',
        ),
      ) as ConfigurationError;
      expect(issuer.expected, 'https://id.example.com');
      expect(issuer.received, 'https://evil.example.com');
      final rejected = errorFromMessage(
        msg(
          configuration,
          'tokenRequestRejected',
          code: 'invalid_scope',
          errorDescription: 'no',
        ),
      ) as ConfigurationError;
      expect(rejected.code, 'invalid_scope');
      expect(rejected.description, 'no');
    });

    test('every ID-token rejection reason keeps its name, and an unknown one is unknown with its text', () {
      for (final r in IdTokenRejection.values) {
        if (r == IdTokenRejection.unknown) continue;
        final e = errorFromMessage(
          msg(configuration, 'idTokenRejected', idTokenRejection: r.name),
        ) as ConfigurationError;
        expect(e.idTokenRejection, r);
      }
      final novel = errorFromMessage(
        msg(configuration, 'idTokenRejected', idTokenRejection: 'novelty'),
      ) as ConfigurationError;
      expect(novel.idTokenRejection, IdTokenRejection.unknown);
      expect(novel.text, 'novelty');
    });

    test('the edge_client_unknown case is the unknown detail with its name as text and its stable code', () {
      final e = errorFromMessage(
        msg(
          configuration,
          'unknown',
          detail: 'edge_client_unknown',
          sdkCode: 'configuration.edge_client_unknown',
        ),
      ) as ConfigurationError;
      expect(e.detail, ConfigurationDetail.unknown);
      expect(e.text, 'edge_client_unknown');
      expect(e.sdkCode, 'configuration.edge_client_unknown');
    });

    test('a kind this Dart does not know is unknown in its category, never a guessed real case', () {
      final r =
          errorFromMessage(msg(recoverable, 'brandNew')) as RecoverableError;
      expect(r.cause, RecoverableCause.unknown);
      expect(r.detail, 'brandNew');
      expect(r.cause, isNot(RecoverableCause.network));

      final a = errorFromMessage(
        msg(reauthenticate, 'brandNew'),
      ) as ReauthenticateError;
      expect(a.reason, ReauthenticateReason.unknown);
      expect(a.detail, 'brandNew');

      final c = errorFromMessage(
        msg(configuration, 'brandNew', sdkCode: 'configuration.brand_new'),
      ) as ConfigurationError;
      expect(c.detail, ConfigurationDetail.unknown);
      expect(c.text, 'brandNew');
      expect(c.sdkCode, 'configuration.brand_new');
    });

    test('a reauthenticate unknown sent by native keeps the name it carries in detail', () {
      final a = errorFromMessage(
        msg(reauthenticate, 'unknown', detail: 'FutureReason'),
      ) as ReauthenticateError;
      expect(a.reason, ReauthenticateReason.unknown);
      expect(a.detail, 'FutureReason');
    });
  });

  group('toMessage and the small mappings', () {
    test('maps the session states one to one and in order', () {
      for (var i = 0; i < SessionState.values.length; i++) {
        expect(
          fromMessage(VersolaSessionStateMessage.values[i]),
          SessionState.values[i],
        );
      }
      expect(
        VersolaSessionStateMessage.values.map((e) => e.name),
        SessionState.values.map((e) => e.name),
      );
    });

    test('maps the prompts one to one', () {
      expect(
        VersolaPromptMessage.values.map((e) => e.name),
        Prompt.values.map((e) => e.name),
      );
      for (final p in Prompt.values) {
        expect(
          loginOptionsToMessage(LoginOptions(prompt: p)).prompt?.name,
          p.name,
        );
      }
    });

    test('redacts the claims in toString', () {
      final claims = claimsFromMessage(
        VersolaIdTokenClaimsMessage(
          subject: 'alice-sub',
          issuer: 'https://id.example.com',
          audience: ['app'],
          issuedAtEpochSeconds: 1,
          expiresAtEpochSeconds: 2,
          amr: [],
          all: {'email': 'alice@example.com'},
        ),
      );
      expect(claims.toString(), isNot(contains('alice')));
    });
  });

  group('value semantics', () {
    test('VersolaConfiguration and LoginOptions are equal by value', () {
      const a = VersolaConfiguration(
        edgeUrl: 'https://id.example.com',
        clientId: 'app',
        redirectUri: 'https://app.example.com/oauth',
      );
      const b = VersolaConfiguration(
        edgeUrl: 'https://id.example.com',
        clientId: 'app',
        redirectUri: 'https://app.example.com/oauth',
      );
      const c = VersolaConfiguration(
        edgeUrl: 'https://id.example.com',
        clientId: 'app',
        redirectUri: 'https://app.example.com/oauth',
        issuer: 'https://id.example.com',
      );
      expect(a, b);
      expect(a.hashCode, b.hashCode);
      expect(a, isNot(c), reason: 'an explicit issuer is not an absent one');
      expect(
        LoginOptions(scopes: {'a', 'b'}, claims: '{}'),
        LoginOptions(scopes: {'b', 'a'}, claims: '{}'),
      );
      expect(LoginOptions(claims: '{}'), isNot(LoginOptions(claims: '[]')));
    });

    test(
      'a collection mutated after construction does not change LoginOptions',
      () {
        final scopes = <String>{'a'};
        final options = LoginOptions(scopes: scopes);
        scopes.add('b');
        expect(options.scopes, {'a'});
        expect(() => options.scopes.add('c'), throwsUnsupportedError);
      },
    );
  });
}
