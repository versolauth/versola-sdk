// A minimal app over the binding: sign-in, refresh, sign-out, the session state and the error
// categories on screen. example.com configuration and no real client id (`flutter.md`); point
// it at a provider with --dart-define=ISSUER=... CLIENT_ID=... REDIRECT_URI=....
import 'dart:async';

import 'package:flutter/material.dart';
import 'package:versola_oauth/versola_oauth.dart';

const issuer = String.fromEnvironment(
  'ISSUER',
  defaultValue: 'https://id.example.com',
);
const clientId = String.fromEnvironment(
  'CLIENT_ID',
  defaultValue: 'example-app',
);
const redirectUri = String.fromEnvironment(
  'REDIRECT_URI',
  defaultValue: 'https://app.example.com/oauth',
);
const postLogoutRedirectUri = String.fromEnvironment(
  'POST_LOGOUT_REDIRECT_URI',
  defaultValue: 'https://app.example.com/signed-out',
);

void main() => runApp(const ExampleApp());

class ExampleApp extends StatelessWidget {
  const ExampleApp({super.key});

  @override
  Widget build(BuildContext context) => const MaterialApp(home: SessionPage());
}

class SessionPage extends StatefulWidget {
  const SessionPage({super.key});

  @override
  State<SessionPage> createState() => _SessionPageState();
}

class _SessionPageState extends State<SessionPage> {
  OAuthClient? _client;
  StreamSubscription<SessionState>? _states;
  SessionState? _state;
  String _log = '';

  @override
  void initState() {
    super.initState();
    _create();
  }

  Future<void> _create() async {
    await _run('create', () async {
      final client = await OAuthClient.create(
        const OAuthConfiguration(
          issuer: issuer,
          clientId: clientId,
          redirectUri: redirectUri,
          postLogoutRedirectUri: postLogoutRedirectUri,
          scopes: {'openid', 'profile'},
        ),
      );
      _states = client.sessionStates().listen(
        (state) => setState(() => _state = state),
      );
      setState(() => _client = client);
    });
  }

  /// Every call is wrapped the same way: the category is what the app decides on. A
  /// Recoverable is retried or shown; a Reauthenticate sends the user to sign in; a StepUp is
  /// answered with stepUp(); a Configuration is a deployment mistake to fix, not to catch.
  Future<void> _run(String name, Future<void> Function() action) async {
    try {
      await action();
      _append('$name: ok');
    } on RecoverableError catch (e) {
      _append(
        '$name: recoverable (${e.cause.name}) — retry or ask the user again',
      );
    } on ReauthenticateError catch (e) {
      _append('$name: reauthenticate (${e.reason.name}) — sign in again');
    } on StepUpError catch (e) {
      _append(
        '$name: step-up required (${e.acrValues.join(" ")}) — answering with stepUp()',
      );
      await _run('stepUp', () => _client!.stepUp(e));
    } on ConfigurationError catch (e) {
      _append('$name: configuration (${e.detail.name}) — ${e.message}');
    }
  }

  void _append(String line) => setState(() => _log = '$line\n$_log');

  @override
  void dispose() {
    _states?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final client = _client;
    return Scaffold(
      appBar: AppBar(title: const Text('versola_oauth example')),
      body: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text('Issuer: $issuer'),
            Text(
              'State: ${_state?.name ?? '…'}',
              style: Theme.of(context).textTheme.titleMedium,
            ),
            const SizedBox(height: 12),
            Wrap(
              spacing: 8,
              children: [
                FilledButton(
                  onPressed: client == null
                      ? null
                      : () => _run('login', client.login),
                  child: const Text('Sign in'),
                ),
                OutlinedButton(
                  onPressed: client == null
                      ? null
                      : () => _run('refresh', client.refresh),
                  child: const Text('Refresh'),
                ),
                OutlinedButton(
                  onPressed: client == null
                      ? null
                      : () => _run('accessToken', () async {
                          final token = await client.accessToken();
                          // The value is never shown or logged; the scheme says what kind it is.
                          _append(
                            'accessToken: ${token.tokenType}, ${token.value.length} characters',
                          );
                        }),
                  child: const Text('Access token'),
                ),
                OutlinedButton(
                  onPressed: client == null
                      ? null
                      : () => _run('userInfo', () async {
                          final info = await client.userInfo();
                          _append('userInfo: ${info.claims.length} claims');
                        }),
                  child: const Text('UserInfo'),
                ),
                OutlinedButton(
                  onPressed: client == null
                      ? null
                      : () => _run('logout', () async {
                          final outcome = await client.logout();
                          _append(
                            'logout: sessionEnded=${outcome.sessionEnded} tokenRevoked=${outcome.tokenRevoked}',
                          );
                        }),
                  child: const Text('Sign out'),
                ),
              ],
            ),
            const SizedBox(height: 12),
            Expanded(
              child: SingleChildScrollView(
                child: Text(
                  _log,
                  style: const TextStyle(fontFamily: 'monospace'),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
