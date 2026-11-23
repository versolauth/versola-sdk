import 'package:versola_oauth/versola_oauth.dart'
    show IdTokenClaims, LogoutOptions, LogoutOutcome, SessionState, StepUpError;

import 'configuration.dart';

/// The operations of [Versola] that an app's own code calls, as an interface, so that the code is
/// tested against a fake of your own (`implements VersolaApi`) and not a live client
/// (`spec/versola-sdk-api.md` section 13). Creating a client and `httpClient()` stay on the
/// client: the latter returns a `package:http` client that a fake cannot honour.
///
/// There is no `accessToken()`: a key-bound token is useless without a proof for the exact
/// request, so a token handed to app code could only be logged (`spec/versola-sdk-api.md`
/// section 10).
abstract interface class VersolaApi {
  /// The state machine, observable. The first value is the restored state.
  Stream<SessionState> sessionStates();

  /// The current state, restored first.
  Future<SessionState> currentSessionState();

  /// The claims of the last validated ID token, or null when there is no session.
  Future<IdTokenClaims?> claims();

  /// Signs the user in through the system browser.
  Future<void> login([LoginOptions? options]);

  /// Answers a `StepUpError` by re-authorizing at the context it names.
  Future<void> stepUp(StepUpError challenge, [LoginOptions? options]);

  /// Ends the session on this device and, where the edge allows, at the issuer.
  Future<LogoutOutcome> logout([LogoutOptions options = const LogoutOptions()]);

  /// Spends the stored refresh token once, now.
  Future<void> refresh();

  /// Which key tier the DPoP key reached, or null when there is no key yet.
  Future<String?> keyAttestation();
}
