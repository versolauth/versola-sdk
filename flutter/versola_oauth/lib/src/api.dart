import 'errors.dart';
import 'types.dart';

/// The operations of `OAuthClient` that an app's own code calls, as an interface, so that the code
/// is tested against a fake of your own (`implements OAuthApi`) and not a live client
/// (`spec/oauth-sdk-api.md` section 17). The HTTP helper, `httpClient()`, stays on the client: it
/// returns a `package:http` client that a fake cannot honour.
abstract interface class OAuthApi {
  /// The state machine, observable. The first value is the restored state.
  Stream<SessionState> sessionStates();

  /// The current state, restored first.
  Future<SessionState> currentSessionState();

  /// The claims of the last validated ID token, or null when there is no session.
  Future<IdTokenClaims?> claims();

  /// Signs the user in through the system browser.
  Future<void> login([LoginOptions? options]);

  /// Answers a [StepUpError] by re-authorizing at the context it names.
  Future<void> stepUp(StepUpError challenge, [LoginOptions? options]);

  /// Ends the session on this device and, where the provider supports it, at the provider.
  Future<LogoutOutcome> logout([LogoutOptions options = const LogoutOptions()]);

  /// A token fit to send now, refreshed first if it is due.
  Future<AccessToken> accessToken();

  /// Spends the stored refresh token once, now.
  Future<void> refresh();

  /// The provider's UserInfo for the signed-in user.
  Future<UserInfo> userInfo();

  /// Which key tier the DPoP key reached, or null under bearer.
  Future<String?> keyAttestation();
}
