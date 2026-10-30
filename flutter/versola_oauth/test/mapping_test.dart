import 'package:flutter_test/flutter_test.dart';
import 'package:versola_oauth/src/mapping.dart';
import 'package:versola_oauth/src/messages.g.dart';
import 'package:versola_oauth/versola_oauth.dart';

void main() {
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
        const OAuthConfiguration(
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
