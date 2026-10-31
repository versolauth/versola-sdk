## 0.2.0

- A redirect that is not the awaited response is ignored while the login waits (#118)
- Update vulnerable build tooling and limit debug mode (#116)
- build(deps): bump androidx.test.uiautomator:uiautomator from 2.3.0 to 2.4.0 in /flutter/versola_oauth/example/android in the gradle group (#112)
- android: run the SDK's blocking work on its own dispatcher (#115)
- android: refresh persistence order, no wipe without a grant, expiry, cancel API (audit batch) (#109)
- android: storage, DPoP key and redirect hardening (audit batch) (#108)
- build(deps): bump cupertino_icons in /flutter/versola_oauth/example (#114)
- ios: refresh persistence order, no wipe without a grant, HTTP limits, expiry (audit batch) (#107)
- ci: fix security.yml, harden workflows, verify Gradle dependencies (audit batch) (#106)
- ios: DPoP clock skew, locked-device errors, Keychain hardening (audit batch) (#105)
- flutter: authenticated HTTP client through the native bridge (#104)
- ios oauth: resume a cold-started authorization from create, as Android does (#103)
- android: Publish each AAR's own minCompileSdk instead of the build's compileSdk 37 (#102)
- android: Match iOS on maxBackoff below initialBackoff and on UserInfo's other answers (#101)
- Flutter plugin: resolve the SDK root from the manifest's real location so the git dependency builds on iOS (#97)
- Server errors, Retry-After and a cooldown: implementation on Android, iOS and the Flutter bridge (follows #95) (#96)
- build(deps): bump the gradle group (#83)
- spec: Define server-error handling per operation, Retry-After and the cooldown (#95)
- README: Drop the pre-release notice and add install instructions for 0.1.0 (#93)

## 0.1.0

- Initial binding of the generic OAuth SDK (issue #46, B6): `OAuthClient` with `login`,
  `stepUp`, `logout`, `accessToken`, `refresh`, `claims()`, `currentSessionState()`,
  `userInfo`, `keyAttestation` and `sessionStates()`, over a Pigeon bridge to the Android and
  iOS facades.
