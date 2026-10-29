/// The error taxonomy of `spec/errors.md`: four categories, and the category is the contract.
/// Mirrors the native `VersolaError` / `OAuthError` case for case, so an app switches on the
/// category first and reads the payload second. Nothing here carries a credential.
sealed class OAuthError implements Exception {
  const OAuthError(this.message);

  /// A short, log-safe description.
  final String message;

  @override
  String toString() => message;
}

/// Transient or user-driven: the app may retry, or ask the user again.
final class RecoverableError extends OAuthError {
  const RecoverableError(
    this.cause,
    super.message, {
    this.detail,
    this.attempts,
    this.elapsed,
    this.origin,
  });
  final RecoverableCause cause;
  final String? detail;
  final int? attempts;
  final Duration? elapsed;
  final String? origin;
}

enum RecoverableCause {
  userCancelled,
  systemCancelled,
  pendingRequestExpired,
  network,
  unlockRequired,
  nonceLoop,

  /// A native cause this version of the binding does not know; `detail` carries its name. Not
  /// a reason to retry: the app cannot tell what it means, so it must not loop on it.
  unknown,
}

/// The session is over; the user signs in again.
final class ReauthenticateError extends OAuthError {
  const ReauthenticateError(
    this.reason,
    super.message, {
    this.code,
    this.detail,
  });
  final ReauthenticateReason reason;
  final String? code;

  /// The native name of a reason this version of the binding does not know
  /// ([ReauthenticateReason.unknown]).
  final String? detail;
}

enum ReauthenticateReason {
  authorizationDenied,
  interactionRequired,
  credentialsInvalidated,
  grantRejected,
  sessionRejected,
  sessionExpired,

  /// A native reason this version of the binding does not know; `detail` carries its name.
  /// Whether it ends the session is the native SDK's call, so the app asks the user to sign in
  /// again only if its own flow needs a session.
  unknown,
}

/// RFC 9470: the resource server wants a stronger authentication context.
final class StepUpError extends OAuthError {
  const StepUpError(super.message, {required this.acrValues, this.maxAge});
  final List<String> acrValues;
  final int? maxAge;
}

/// A deployment, integration or provider problem no retry fixes.
final class ConfigurationError extends OAuthError {
  const ConfigurationError(
    this.detail,
    super.message, {
    this.code,
    this.description,
    this.text,
    this.expected,
    this.received,
    this.field,
    this.capability,
    this.idTokenRejection,
  });
  final ConfigurationDetail detail;
  final String? code;
  final String? description;
  final String? text;
  final String? expected;
  final String? received;
  final String? field;
  final String? capability;
  final IdTokenRejection? idTokenRejection;
}

enum ConfigurationDetail {
  stateMismatch,
  issuerMismatch,
  malformedAuthorizationResponse,
  authorizationRejected,
  tokenRequestRejected,
  tokenResponseMalformed,
  discoveryFieldMissing,
  discoveryIssuerMismatch,
  discoveryMalformed,
  invalidConfiguration,
  noBrowserAvailable,
  idTokenRejected,
  userInfoRejected,
  providerUnsupported,
  hardwareBindingUnavailable,

  /// A native detail this version of the binding does not know; `text` carries its name.
  unknown,
}

/// Why an ID token was refused (`spec/oauth-sdk-api.md` section 11).
enum IdTokenRejection {
  signature,
  algorithm,
  issuer,
  audience,
  expired,
  issuedAt,
  nonce,
  authTime,
  malformed,
  accessTokenHash,

  /// A native rejection this version of the binding does not know; the error's `text` carries
  /// its name.
  unknown,
}
