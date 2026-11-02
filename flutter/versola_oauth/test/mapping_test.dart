import 'package:flutter_test/flutter_test.dart';
import 'package:versola_oauth/src/mapping.dart';
import 'package:versola_oauth/src/messages.g.dart';
import 'package:versola_oauth/versola_oauth.dart';

void main() {
  group('sdkCode (the stable code of spec/errors.md)', () {
    ErrorMessage message(
      ErrorCategoryMessage category,
      String kind, {
      String? sdkCode,
      String? code,
    }) => ErrorMessage(
      category: category,
      kind: kind,
      message: 'm',
      code: code,
      sdkCode: sdkCode,
    );

    test(
      'the native code crosses unchanged and is apart from the provider code',
      () {
        final e = errorFromMessage(
          message(
            ErrorCategoryMessage.configuration,
            'tokenRequestRejected',
            sdkCode: 'configuration.token_request_rejected',
            code: 'invalid_scope',
          ),
        ) as ConfigurationError;
        expect(e.sdkCode, 'configuration.token_request_rejected');
        expect(e.code, 'invalid_scope');
      },
    );

    test('a case this Dart does not know keeps the native code, never a guessed one', () {
      final e = errorFromMessage(
        message(
          ErrorCategoryMessage.recoverable,
          'somethingNew',
          sdkCode: 'recoverable.something_new',
        ),
      );
      expect(e, isA<RecoverableError>());
      expect(e.sdkCode, 'recoverable.something_new');
    });

    test('an error built in Dart derives the same code from its case', () {
      expect(
        const RecoverableError(
          RecoverableCause.pendingRequestExpired,
          'm',
        ).sdkCode,
        'recoverable.pending_request_expired',
      );
      expect(
        const ReauthenticateError(
          ReauthenticateReason.sessionRejected,
          'm',
        ).sdkCode,
        'reauthenticate.session_rejected',
      );
      expect(const StepUpError('m', acrValues: ['c2']).sdkCode, 'step_up');
      expect(
        const ConfigurationError(
          ConfigurationDetail.stateMismatch,
          'm',
        ).sdkCode,
        'configuration.state_mismatch',
      );
    });

    test('the code does not depend on the payload', () {
      expect(
        const RecoverableError(
          RecoverableCause.network,
          'a',
          attempts: 1,
        ).sdkCode,
        const RecoverableError(
          RecoverableCause.network,
          'b',
          attempts: 9,
        ).sdkCode,
      );
    });
  });

  group('errorFromMessage', () {
    test('rebuilds every category with its payload', () {
      final recoverable = errorFromMessage(
        ErrorMessage(
          category: ErrorCategoryMessage.recoverable,
          kind: 'network',
          message: 'recoverable: network',
          detail: 'timeout',
          attempts: 3,
          elapsedMillis: 1200,
        ),
      );
      expect(
        recoverable,
        isA<RecoverableError>()
            .having((e) => e.cause, 'cause', RecoverableCause.network)
            .having((e) => e.attempts, 'attempts', 3)
            .having(
              (e) => e.elapsed,
              'elapsed',
              const Duration(milliseconds: 1200),
            ),
      );

      final server = errorFromMessage(
        ErrorMessage(
          category: ErrorCategoryMessage.recoverable,
          kind: 'server',
          message: 'recoverable: server',
          status: 429,
          retryAfterMillis: 30000,
          attempts: 1,
        ),
      );
      expect(
        server,
        isA<RecoverableError>()
            .having((e) => e.cause, 'cause', RecoverableCause.server)
            .having((e) => e.status, 'status', 429)
            .having(
              (e) => e.retryAfter,
              'retryAfter',
              const Duration(seconds: 30),
            )
            .having((e) => e.attempts, 'attempts', 1),
      );

      // No Retry-After is null, not a zero: an app that waits zero is hammering.
      final plain = errorFromMessage(
        ErrorMessage(
          category: ErrorCategoryMessage.recoverable,
          kind: 'server',
          message: 'recoverable: server',
          status: 500,
        ),
      );
      expect(
        plain,
        isA<RecoverableError>().having(
          (e) => e.retryAfter,
          'retryAfter',
          isNull,
        ),
      );

      final reauth = errorFromMessage(
        ErrorMessage(
          category: ErrorCategoryMessage.reauthenticate,
          kind: 'interactionRequired',
          message: 'reauthenticate',
          code: 'login_required',
        ),
      );
      expect(
        reauth,
        isA<ReauthenticateError>()
            .having(
              (e) => e.reason,
              'reason',
              ReauthenticateReason.interactionRequired,
            )
            .having((e) => e.code, 'code', 'login_required'),
      );

      final stepUp = errorFromMessage(
        ErrorMessage(
          category: ErrorCategoryMessage.stepUp,
          kind: 'stepUp',
          message: 'step-up',
          acrValues: ['urn:acr:mfa'],
          maxAge: 300,
        ),
      );
      expect(
        stepUp,
        isA<StepUpError>()
            .having((e) => e.acrValues, 'acrValues', ['urn:acr:mfa'])
            .having((e) => e.maxAge, 'maxAge', 300),
      );

      final configuration = errorFromMessage(
        ErrorMessage(
          category: ErrorCategoryMessage.configuration,
          kind: 'idTokenRejected',
          message: 'configuration',
          idTokenRejection: 'accessTokenHash',
        ),
      );
      expect(
        configuration,
        isA<ConfigurationError>()
            .having(
              (e) => e.detail,
              'detail',
              ConfigurationDetail.idTokenRejected,
            )
            .having(
              (e) => e.idTokenRejection,
              'rejection',
              IdTokenRejection.accessTokenHash,
            ),
      );
    });

    test(
      'names an unknown case unknown and keeps its name, in every category',
      () {
        final configuration = errorFromMessage(
          ErrorMessage(
            category: ErrorCategoryMessage.configuration,
            kind: 'somethingNew',
            message: 'configuration: somethingNew',
          ),
        );
        expect(
          configuration,
          isA<ConfigurationError>()
              .having((e) => e.detail, 'detail', ConfigurationDetail.unknown)
              .having((e) => e.text, 'text', 'somethingNew'),
        );

        // Not `network`: a guessed transient cause is how an app starts a retry loop.
        final recoverable = errorFromMessage(
          ErrorMessage(
            category: ErrorCategoryMessage.recoverable,
            kind: 'somethingNew',
            message: 'recoverable',
          ),
        );
        expect(
          recoverable,
          isA<RecoverableError>()
              .having((e) => e.cause, 'cause', RecoverableCause.unknown)
              .having((e) => e.detail, 'detail', 'somethingNew'),
        );

        // Not `grantRejected`: a guessed reason would sign the user out for a case that may
        // not mean that.
        final reauthenticate = errorFromMessage(
          ErrorMessage(
            category: ErrorCategoryMessage.reauthenticate,
            kind: 'somethingNew',
            message: 'reauthenticate',
          ),
        );
        expect(
          reauthenticate,
          isA<ReauthenticateError>()
              .having((e) => e.reason, 'reason', ReauthenticateReason.unknown)
              .having((e) => e.detail, 'detail', 'somethingNew'),
        );

        // Not `malformed`: an unknown ID-token rejection is not a malformed token.
        final rejection = errorFromMessage(
          ErrorMessage(
            category: ErrorCategoryMessage.configuration,
            kind: 'idTokenRejected',
            message: 'configuration: idTokenRejected',
            idTokenRejection: 'somethingNew',
          ),
        );
        expect(
          rejection,
          isA<ConfigurationError>()
              .having(
                (e) => e.detail,
                'detail',
                ConfigurationDetail.idTokenRejected,
              )
              .having(
                (e) => e.idTokenRejection,
                'rejection',
                IdTokenRejection.unknown,
              )
              .having((e) => e.text, 'text', 'somethingNew'),
        );
      },
    );

    test(
      'never carries a credential: the message is what the native side wrote',
      () {
        final e = errorFromMessage(
          ErrorMessage(
            category: ErrorCategoryMessage.reauthenticate,
            kind: 'grantRejected',
            message: 'reauthenticate: GrantRejected',
          ),
        );
        expect(e.toString(), 'reauthenticate: GrantRejected');
      },
    );
  });

  group('toMessage', () {
    test('carries the configuration field for field', () {
      final m = toMessage(
        OAuthConfiguration(
          endpoints: ProviderEndpoints(
            issuer: 'https://id.example.com',
            authorizationEndpoint: 'https://id.example.com/authorize',
            tokenEndpoint: 'https://id.example.com/token',
            jwksUri: 'https://id.example.com/jwks',
          ),
          clientId: 'app',
          redirectUri: 'https://app.example.com/oauth',
          scopes: {'openid', 'profile'},
          tokenBinding: TokenBinding.dpopRequireHardware,
          pushedAuthorization: PushedAuthorization.required,
          protectedOrigins: {'https://api.example.com'},
          unlockPolicy: UnlockPolicy.onAppUnlock,
          clockSkewTolerance: Duration(seconds: 30),
          retryPolicy: RetryPolicy(totalBudget: Duration(seconds: 10)),
        ),
      );
      expect(m.issuer, isNull);
      expect(m.endpoints?.issuer, 'https://id.example.com');
      expect(m.scopes, unorderedEquals(['openid', 'profile']));
      expect(m.tokenBinding, TokenBindingMessage.dpopRequireHardware);
      expect(m.pushedAuthorization, PushedAuthorizationMessage.required);
      expect(m.unlockPolicy, UnlockPolicyMessage.onAppUnlock);
      expect(m.clockSkewToleranceSeconds, 30);
      expect(m.retryPolicy?.totalBudgetMillis, 10000);
    });

    test('maps the session states one to one and in order', () {
      for (final state in SessionStateMessage.values) {
        expect(fromMessage(state).name, state.name);
      }
    });

    test('redacts the access token and the claims in toString', () {
      expect(
        const AccessToken(
          value: 'secret-value',
          tokenType: 'Bearer',
        ).toString(),
        isNot(contains('secret')),
      );
      expect(
        claimsFromMessage(
          IdTokenClaimsMessage(
            subject: 'alice',
            issuer: 'https://id.example.com',
            audience: ['app'],
            issuedAtEpochSeconds: 1,
            expiresAtEpochSeconds: 2,
            amr: [],
            all: {},
          ),
        ).toString(),
        isNot(contains('alice')),
      );
    });
  });
}
