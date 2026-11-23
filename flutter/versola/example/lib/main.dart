// A minimal app over the binding: create the client, show the session state, sign in and out.
// example.com configuration and no real client id (`flutter.md`); point it at a deployment with
// --dart-define=EDGE_URL=... CLIENT_ID=... REDIRECT_URI=....
import 'dart:async';

import 'package:flutter/material.dart';
import 'package:versola/versola.dart';

const edgeUrl = String.fromEnvironment(
  'EDGE_URL',
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
  Versola? _client;
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
      final client = await Versola.create(
        const VersolaConfiguration(
          edgeUrl: edgeUrl,
          clientId: clientId,
          redirectUri: redirectUri,
          postLogoutRedirectUri: postLogoutRedirectUri,
        ),
      );
      _states = client.sessionStates().listen(
        (state) => setState(() => _state = state),
      );
      setState(() => _client = client);
    });
  }

  /// Every call is wrapped the same way: the category is what the app decides on.
  Future<void> _run(String name, Future<void> Function() action) async {
    try {
      await action();
      _append('$name: ok');
    } on RecoverableError catch (e) {
      _append('$name: recoverable (${e.cause.name})');
    } on ReauthenticateError catch (e) {
      _append('$name: reauthenticate (${e.reason.name}) — sign in again');
    } on StepUpError catch (e) {
      _append('$name: step-up required (${e.acrValues.join(" ")})');
    } on ConfigurationError catch (e) {
      // `sdkCode` names the case, including the ones that have no ConfigurationDetail value,
      // such as 'configuration.edge_client_unknown'.
      _append('$name: configuration (${e.sdkCode})');
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
      appBar: AppBar(title: const Text('versola example')),
      body: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            const Text('Edge: $edgeUrl'),
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
                      : () => _run('logout', client.logout),
                  child: const Text('Sign out'),
                ),
              ],
            ),
            const SizedBox(height: 12),
            Expanded(child: SingleChildScrollView(child: Text(_log))),
          ],
        ),
      ),
    );
  }
}
