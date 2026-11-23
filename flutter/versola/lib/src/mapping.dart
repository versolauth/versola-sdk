import 'package:flutter/services.dart' show PlatformException;
import 'package:versola_oauth/versola_oauth.dart'
    show
        ConfigurationDetail,
        ConfigurationError,
        IdTokenClaims,
        IdTokenRejection,
        LogoutOutcome,
        OAuthError,
        Prompt,
        ReauthenticateError,
        ReauthenticateReason,
        RecoverableCause,
        RecoverableError,
        SessionState,
        StepUpError,
        UnlockPolicy;

import 'configuration.dart';
import 'messages.g.dart';

/// Runs one host call and turns a channel-level failure into a typed error. Native code catches
/// everything and answers with a Result, so a `PlatformException` here means the call never
/// reached it (no plugin registered, a malformed reply, a native crash in the codec): the
/// category is `Configuration`, and only the exception's code is kept, never its message, which
/// is native text and a stack trace (`flutter.md`: no secret in a `PlatformException` message).
Future<T> guarded<T>(Future<T> Function() call) async {
  try {
    return await call();
  } on PlatformException catch (e) {
    throw asOAuthError(e);
  }
}

/// Any failure that reaches the app through this binding is an [OAuthError] (`flutter.md`,
/// Bridge). A channel failure keeps only its code, as [guarded] does; anything else (a codec
/// error from a native side newer than this Dart, say) is a `Configuration` naming only the
/// exception's type, never its message.
OAuthError asOAuthError(Object error) {
  if (error is OAuthError) return error;
  if (error is PlatformException) {
    return ConfigurationError(
      ConfigurationDetail.invalidConfiguration,
      'configuration: the native bridge failed (${error.code})',
      text: 'bridge failure: ${error.code}',
    );
  }
  return ConfigurationError(
    ConfigurationDetail.unknown,
    'configuration: the native bridge answered with something this version cannot read (${error.runtimeType})',
    text: 'bridge failure: ${error.runtimeType}',
  );
}

Future<void> unwrapVoid(Future<VersolaVoidResult> result) async {
  switch (await guarded(() => result)) {
    case VersolaVoidOk():
      return;
    case VersolaVoidFailure(:final error):
      throw errorFromMessage(error);
  }
}

/// The bridge carries whole seconds and whole milliseconds; a finer [Duration] would be
/// truncated silently (a 400 microsecond backoff would become 0 ms), so it is refused.
void _requireWhole(
  String name,
  Duration value,
  int unitMicroseconds,
  String unit,
) {
  if (value.inMicroseconds % unitMicroseconds != 0) {
    throw ArgumentError.value(
      value,
      name,
      'must be a whole number of $unit; the bridge would truncate it',
    );
  }
}

VersolaConfigurationMessage toMessage(VersolaConfiguration c) {
  _requireWhole('clockSkewTolerance', c.clockSkewTolerance, 1000000, 'seconds');
  final retry = c.retryPolicy;
  if (retry != null) {
    _requireWhole(
      'retryPolicy.initialBackoff',
      retry.initialBackoff,
      1000,
      'milliseconds',
    );
    _requireWhole(
      'retryPolicy.maxBackoff',
      retry.maxBackoff,
      1000,
      'milliseconds',
    );
    _requireWhole(
      'retryPolicy.totalBudget',
      retry.totalBudget,
      1000,
      'milliseconds',
    );
  }
  return VersolaConfigurationMessage(
    edgeUrl: c.edgeUrl,
    clientId: c.clientId,
    redirectUri: c.redirectUri,
    issuer: c.issuer,
    postLogoutRedirectUri: c.postLogoutRedirectUri,
    requireHardwareKey: c.requireHardwareKey,
    unlockPolicy: c.unlockPolicy == UnlockPolicy.none
        ? VersolaUnlockPolicyMessage.none
        : VersolaUnlockPolicyMessage.onAppUnlock,
    clockSkewToleranceSeconds: c.clockSkewTolerance.inSeconds,
    retryPolicy: retry == null
        ? null
        : VersolaRetryPolicyMessage(
            maxAttemptsPerOrigin: retry.maxAttemptsPerOrigin,
            maxTotalAttempts: retry.maxTotalAttempts,
            initialBackoffMillis: retry.initialBackoff.inMilliseconds,
            backoffMultiplier: retry.backoffMultiplier,
            maxBackoffMillis: retry.maxBackoff.inMilliseconds,
            totalBudgetMillis: retry.totalBudget.inMilliseconds,
          ),
  );
}

VersolaLoginOptionsMessage loginOptionsToMessage(LoginOptions o) =>
    VersolaLoginOptionsMessage(
      scopes: o.scopes.toList(),
      acrValues: o.acrValues,
      maxAge: o.maxAge,
      prompt: switch (o.prompt) {
        null => null,
        Prompt.none => VersolaPromptMessage.none,
        Prompt.login => VersolaPromptMessage.login,
        Prompt.consent => VersolaPromptMessage.consent,
        Prompt.selectAccount => VersolaPromptMessage.selectAccount,
        Prompt.create => VersolaPromptMessage.create,
      },
      loginHint: o.loginHint,
      uiLocales: o.uiLocales,
      resources: o.resources,
      claims: o.claims,
      authorizationDetails: o.authorizationDetails,
      ephemeralBrowser: o.ephemeralBrowser,
    );

/// A state this Dart does not know (a newer native side) is a typed error, never a `RangeError`
/// and never a guessed real state.
SessionState fromMessage(VersolaSessionStateMessage m) {
  if (m.index < 0 || m.index >= SessionState.values.length) {
    throw ConfigurationError(
      ConfigurationDetail.unknown,
      'configuration: the native side reported a session state this version does not know',
      text: 'sessionState: ${m.index}',
    );
  }
  return SessionState.values[m.index];
}

LogoutOutcome logoutOutcomeFromMessage(VersolaLogoutOutcomeMessage m) =>
    LogoutOutcome(sessionEnded: m.sessionEnded, tokenRevoked: m.tokenRevoked);

IdTokenClaims claimsFromMessage(VersolaIdTokenClaimsMessage m) => IdTokenClaims(
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
///
/// The Versola facade's own `edge_client_unknown` has no Dart enum value in `versola_oauth`, so
/// native sends it as `kind: 'unknown'` with its name in `detail` and its stable code in
/// `sdkCode`; it comes out as `ConfigurationDetail.unknown` with that name as `text` and
/// `sdkCode == 'configuration.edge_client_unknown'`.
OAuthError errorFromMessage(VersolaErrorMessage e) {
  T? byName<T extends Enum>(List<T> values, String? name) {
    for (final v in values) {
      if (v.name == name) return v;
    }
    return null;
  }

  switch (e.category) {
    case VersolaErrorCategoryMessage.recoverable:
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
        sdkCode: e.sdkCode,
      );
    case VersolaErrorCategoryMessage.reauthenticate:
      final reason = byName(ReauthenticateReason.values, e.kind);
      return ReauthenticateError(
        reason ?? ReauthenticateReason.unknown,
        e.message,
        code: e.code,
        detail: reason == null ? e.kind : e.detail,
        sdkCode: e.sdkCode,
      );
    case VersolaErrorCategoryMessage.stepUp:
      return StepUpError(
        e.message,
        acrValues: e.acrValues ?? const <String>[],
        maxAge: e.maxAge,
      );
    case VersolaErrorCategoryMessage.configuration:
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
        sdkCode: e.sdkCode,
        idTokenRejection: e.idTokenRejection == null
            ? null
            : rejection ?? IdTokenRejection.unknown,
      );
  }
}
