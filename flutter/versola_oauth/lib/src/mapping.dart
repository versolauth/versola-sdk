import 'package:flutter/services.dart' show PlatformException;

import 'errors.dart';
import 'messages.g.dart';
import 'types.dart';

/// Runs one host call and turns a channel-level failure into a typed error. Native code
/// catches everything and answers with a Result, so a `PlatformException` here means the call
/// never reached it (no plugin registered, a malformed reply, a native crash in the codec): the
/// category is `Configuration`, and only the exception's code is kept, never its message, which
/// is native text and a stack trace (`flutter.md`: no secret in a `PlatformException` message).
Future<T> guarded<T>(Future<T> Function() call) async {
  try {
    return await call();
  } on PlatformException catch (e) {
    throw ConfigurationError(
      ConfigurationDetail.invalidConfiguration,
      'configuration: the native bridge failed (${e.code})',
      text: 'bridge failure: ${e.code}',
    );
  }
}

Future<void> unwrapVoid(Future<VoidResult> result) async {
  switch (await guarded(() => result)) {
    case VoidOk():
      return;
    case VoidFailure(:final error):
      throw errorFromMessage(error);
  }
}

ConfigurationMessage toMessage(OAuthConfiguration c) => ConfigurationMessage(
  issuer: c.issuer,
  endpoints: c.endpoints == null
      ? null
      : EndpointsMessage(
          issuer: c.endpoints!.issuer,
          authorizationEndpoint: c.endpoints!.authorizationEndpoint,
          tokenEndpoint: c.endpoints!.tokenEndpoint,
          jwksUri: c.endpoints!.jwksUri,
          userinfoEndpoint: c.endpoints!.userinfoEndpoint,
          revocationEndpoint: c.endpoints!.revocationEndpoint,
          endSessionEndpoint: c.endpoints!.endSessionEndpoint,
          pushedAuthorizationRequestEndpoint:
              c.endpoints!.pushedAuthorizationRequestEndpoint,
          idTokenSigningAlgValuesSupported:
              c.endpoints!.idTokenSigningAlgValuesSupported,
        ),
  clientId: c.clientId,
  redirectUri: c.redirectUri,
  postLogoutRedirectUri: c.postLogoutRedirectUri,
  scopes: c.scopes.toList(),
  tokenBinding: switch (c.tokenBinding) {
    TokenBinding.bearer => TokenBindingMessage.bearer,
    TokenBinding.dpop => TokenBindingMessage.dpop,
    TokenBinding.dpopRequireHardware => TokenBindingMessage.dpopRequireHardware,
  },
  pushedAuthorization: switch (c.pushedAuthorization) {
    PushedAuthorization.never => PushedAuthorizationMessage.never,
    PushedAuthorization.whenAdvertised =>
      PushedAuthorizationMessage.whenAdvertised,
    PushedAuthorization.required => PushedAuthorizationMessage.required,
  },
  protectedOrigins: c.protectedOrigins.toList(),
  endSessionEndpoint: c.endSessionEndpoint,
  unlockPolicy: c.unlockPolicy == UnlockPolicy.none
      ? UnlockPolicyMessage.none
      : UnlockPolicyMessage.onAppUnlock,
  clockSkewToleranceSeconds: c.clockSkewTolerance.inSeconds,
  retryPolicy: c.retryPolicy == null
      ? null
      : RetryPolicyMessage(
          maxAttemptsPerOrigin: c.retryPolicy!.maxAttemptsPerOrigin,
          maxTotalAttempts: c.retryPolicy!.maxTotalAttempts,
          initialBackoffMillis: c.retryPolicy!.initialBackoff.inMilliseconds,
          backoffMultiplier: c.retryPolicy!.backoffMultiplier,
          maxBackoffMillis: c.retryPolicy!.maxBackoff.inMilliseconds,
          totalBudgetMillis: c.retryPolicy!.totalBudget.inMilliseconds,
        ),
);

LoginOptionsMessage loginOptionsToMessage(LoginOptions o) =>
    LoginOptionsMessage(
      scopes: o.scopes?.toList(),
      prompt: switch (o.prompt) {
        null => null,
        Prompt.none => PromptMessage.none,
        Prompt.login => PromptMessage.login,
        Prompt.consent => PromptMessage.consent,
        Prompt.selectAccount => PromptMessage.selectAccount,
        Prompt.create => PromptMessage.create,
      },
      loginHint: o.loginHint,
      uiLocales: o.uiLocales,
      acrValues: o.acrValues,
      maxAge: o.maxAge,
      resources: o.resources,
      extraParameters: o.extraParameters,
      ephemeralBrowser: o.ephemeralBrowser,
    );

SessionState fromMessage(SessionStateMessage m) => SessionState.values[m.index];

LogoutOutcome logoutOutcomeFromMessage(LogoutOutcomeMessage m) =>
    LogoutOutcome(sessionEnded: m.sessionEnded, tokenRevoked: m.tokenRevoked);

IdTokenClaims claimsFromMessage(IdTokenClaimsMessage m) => IdTokenClaims(
  subject: m.subject,
  issuer: m.issuer,
  audience: m.audience,
  issuedAt: DateTime.fromMillisecondsSinceEpoch(
    m.issuedAtEpochSeconds * 1000,
    isUtc: true,
  ),
  expiresAt: DateTime.fromMillisecondsSinceEpoch(
    m.expiresAtEpochSeconds * 1000,
    isUtc: true,
  ),
  authTime: m.authTimeEpochSeconds == null
      ? null
      : DateTime.fromMillisecondsSinceEpoch(
          m.authTimeEpochSeconds! * 1000,
          isUtc: true,
        ),
  acr: m.acr,
  amr: m.amr,
  authorizedParty: m.authorizedParty,
  all: m.all,
);

/// Rebuilds the sealed hierarchy from the flattened native error: the category first (the
/// contract), then the case by its native name. A case within a known category that this
/// version does not know keeps the category, is named `unknown`, and carries the native name,
/// never a different real case and never a crash (`flutter.md`, Bridge): a guessed `network`
/// would start a retry loop and a guessed `grantRejected` would sign the user out.
OAuthError errorFromMessage(ErrorMessage e) {
  T? byName<T extends Enum>(List<T> values, String? name) {
    for (final v in values) {
      if (v.name == name) return v;
    }
    return null;
  }

  switch (e.category) {
    case ErrorCategoryMessage.recoverable:
      final cause = byName(RecoverableCause.values, e.kind);
      return RecoverableError(
        cause ?? RecoverableCause.unknown,
        e.message,
        detail: cause == null ? e.kind : e.detail,
        attempts: e.attempts,
        elapsed: e.elapsedMillis == null
            ? null
            : Duration(milliseconds: e.elapsedMillis!),
        status: e.status,
        retryAfter: e.retryAfterMillis == null
            ? null
            : Duration(milliseconds: e.retryAfterMillis!),
        origin: e.origin,
      );
    case ErrorCategoryMessage.reauthenticate:
      final reason = byName(ReauthenticateReason.values, e.kind);
      return ReauthenticateError(
        reason ?? ReauthenticateReason.unknown,
        e.message,
        code: e.code,
        detail: reason == null ? e.kind : null,
      );
    case ErrorCategoryMessage.stepUp:
      return StepUpError(
        e.message,
        acrValues: e.acrValues ?? const <String>[],
        maxAge: e.maxAge,
      );
    case ErrorCategoryMessage.configuration:
      final detail = byName(ConfigurationDetail.values, e.kind);
      final rejection = byName(IdTokenRejection.values, e.idTokenRejection);
      return ConfigurationError(
        detail ?? ConfigurationDetail.unknown,
        e.message,
        code: e.code,
        description: e.errorDescription,
        text:
            e.detail ??
            (detail == null
                ? e.kind
                : (e.idTokenRejection != null && rejection == null
                      ? e.idTokenRejection
                      : null)),
        expected: e.expected,
        received: e.received,
        field: e.field,
        capability: e.capability,
        idTokenRejection: e.idTokenRejection == null
            ? null
            : rejection ?? IdTokenRejection.unknown,
      );
  }
}
