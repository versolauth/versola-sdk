import 'dart:convert';

import 'package:crypto/crypto.dart' show sha256;

import 'errors.dart';
import 'messages.g.dart';
import 'types.dart';

/// The native facades key their one-instance-per-configuration registry by the issuer and the
/// client id; the handle is the same derivation so Dart and native agree on identity.
String handleFor(OAuthConfiguration configuration) {
  final issuer = (configuration.issuer ?? configuration.endpoints?.issuer ?? '')
      .replaceAll(RegExp(r'/$'), '');
  final digest = sha256
      .convert(utf8.encode('$issuer\n${configuration.clientId}'))
      .bytes;
  return base64Url.encode(digest).replaceAll('=', '').substring(0, 16);
}

Future<void> unwrapVoid(Future<VoidResult> result) async {
  switch (await result) {
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
/// contract), then the case by its native name. An unknown case within a known category keeps
/// the category and names the case in the text, never a crash (`flutter.md`, Bridge).
OAuthError errorFromMessage(ErrorMessage e) {
  T byName<T extends Enum>(List<T> values, T fallback) =>
      values.firstWhere((v) => v.name == e.kind, orElse: () => fallback);
  switch (e.category) {
    case ErrorCategoryMessage.recoverable:
      return RecoverableError(
        byName(RecoverableCause.values, RecoverableCause.network),
        e.message,
        detail: e.detail,
        attempts: e.attempts,
        elapsed: e.elapsedMillis == null
            ? null
            : Duration(milliseconds: e.elapsedMillis!),
        origin: e.origin,
      );
    case ErrorCategoryMessage.reauthenticate:
      return ReauthenticateError(
        byName(ReauthenticateReason.values, ReauthenticateReason.grantRejected),
        e.message,
        code: e.code,
      );
    case ErrorCategoryMessage.stepUp:
      return StepUpError(
        e.message,
        acrValues: e.acrValues ?? const <String>[],
        maxAge: e.maxAge,
      );
    case ErrorCategoryMessage.configuration:
      return ConfigurationError(
        byName(ConfigurationDetail.values, ConfigurationDetail.unknown),
        e.message,
        code: e.code,
        description: e.errorDescription,
        text:
            e.detail ??
            (ConfigurationDetail.values.any((v) => v.name == e.kind)
                ? null
                : e.kind),
        expected: e.expected,
        received: e.received,
        field: e.field,
        capability: e.capability,
        idTokenRejection: e.idTokenRejection == null
            ? null
            : IdTokenRejection.values.firstWhere(
                (v) => v.name == e.idTokenRejection,
                orElse: () => IdTokenRejection.malformed,
              ),
      );
  }
}
