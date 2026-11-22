// The Versola facade, assembled in this target (see the files beside this one).
//
// The shared core's types are this facade's too (`spec/versola-sdk-api.md` section 13), so they are
// re-exported the way `OAuthClient` re-exports them: an app that imports this module names
// `SessionState`, `OAuthError`, `IdTokenClaims`, `RetryPolicy`, `UnlockPolicy`, `LogoutOutcome` and
// the rest without a second import. From `OAuthClient` exactly the three types that are on this
// surface, and nothing else: that module has a `LoginOptions` and a `LoginRequest` of its own,
// which would make this facade's `LoginOptions` ambiguous in the app that imports both.
@_exported import OAuthCore
@_exported import struct OAuthClient.LogoutOptions
@_exported import struct OAuthClient.KeyAttestation
@_exported import class OAuthClient.AuthenticatedSession
