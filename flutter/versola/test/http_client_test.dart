import 'dart:convert';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/retry.dart';
import 'package:versola/src/messages.g.dart';
import 'package:versola/versola.dart';

import 'client_test.dart' show FakeHost, created;

/// The `package:http` face of the native authenticated client, against a scripted bridge. These
/// prove the request and response mapping, the error mapping and how an app composes the client;
/// that the token is attached, refreshed and replayed is the native tiers' (`testing.md`).
VersolaHttpOk ok({
  int status = 200,
  String? reason = 'OK',
  List<VersolaHttpHeaderMessage> headers = const [],
  List<int> body = const [],
}) => VersolaHttpOk(
  response: VersolaHttpResponseMessage(
    status: status,
    reasonPhrase: reason,
    headers: headers,
    body: Uint8List.fromList(body),
  ),
);

VersolaHttpHeaderMessage header(String name, String value) =>
    VersolaHttpHeaderMessage(name: name, value: value);

VersolaHttpFailure failure(VersolaErrorMessage error) =>
    VersolaHttpFailure(error: error);

final api = Uri.https('id.example.com', '/resources/items', {'page': '2'});

Future<(FakeHost, Versola)> setUp() async {
  final host = FakeHost();
  return (host, await created(host));
}

String headerOf(VersolaHttpRequestMessage r, String name) => r.headers
    .where((h) => h.name.toLowerCase() == name.toLowerCase())
    .map((h) => h.value)
    .join('|');

void main() {
  group('request and response mapping', () {
    test('a request crosses as method, URL, headers and bytes, and the response comes back whole', () async {
      final (host, versola) = await setUp();
      host.answers.add(
        ok(
          status: 201,
          reason: 'Created',
          headers: [header('Content-Type', 'application/json')],
          body: utf8.encode('{"id":1}'),
        ),
      );

      final response = await versola.httpClient().post(
        api,
        headers: {'X-Trace': 'abc'},
        body: utf8.encode('payload'),
      );

      final sent = host.requests.single;
      expect(sent.method, 'POST');
      expect(sent.url, 'https://id.example.com/resources/items?page=2');
      expect(headerOf(sent, 'x-trace'), 'abc');
      expect(utf8.decode(sent.body!), 'payload');
      expect(response.statusCode, 201);
      expect(response.reasonPhrase, 'Created');
      expect(response.body, '{"id":1}');
      expect(response.headers['content-type'], 'application/json');
      expect(response.contentLength, 8);
    });

    test('a request without a body sends none, and a streamed body is collected whole', () async {
      final (host, versola) = await setUp();
      host
        ..answers.add(ok())
        ..answers.add(ok());
      final client = versola.httpClient();

      await client.get(api);
      final streamed = http.StreamedRequest('PUT', api);
      final done = client.send(streamed);
      streamed.sink
        ..add([1, 2])
        ..add([3]);
      await streamed.sink.close();
      await done;

      expect(host.requests[0].body, isNull);
      expect(host.requests[1].body, [1, 2, 3]);
    });

    test('a repeated response header keeps every value, joined as package:http joins them', () async {
      final (host, versola) = await setUp();
      host.answers.add(
        ok(
          status: 401,
          headers: [
            header('WWW-Authenticate', 'Bearer realm="a"'),
            header('www-authenticate', 'DPoP algs="ES256"'),
          ],
        ),
      );

      final response = await versola.httpClient().get(api);

      expect(response.headersSplitValues['www-authenticate'], [
        'Bearer realm="a"',
        'DPoP algs="ES256"',
      ]);
    });

    test(
      'a body larger than a chunk is buffered whole in both directions',
      () async {
        final (host, versola) = await setUp();
        final big = List<int>.generate(300000, (i) => i % 251);
        host.answers.add(ok(body: big));

        final response = await versola.httpClient().post(api, body: big);

        expect(host.requests.single.body, big);
        expect(response.bodyBytes, big);
        expect(response.contentLength, big.length);
      },
    );

    test('a 429 and a 503 are the response, with Retry-After, not an error, and nothing is repeated', () async {
      final (host, versola) = await setUp();
      host
        ..answers.add(ok(status: 429, headers: [header('Retry-After', '7')]))
        ..answers.add(ok(status: 503, headers: [header('Retry-After', '1')]));
      final client = versola.httpClient();

      final limited = await client.get(api);
      final unavailable = await client.get(api);

      expect(limited.statusCode, 429);
      expect(limited.headers['retry-after'], '7');
      expect(unavailable.statusCode, 503);
      expect(host.requests, hasLength(2));
    });

    test('a redirect is returned as one, with its Location, and Dart follows nothing', () async {
      final (host, versola) = await setUp();
      host.answers.add(
        ok(
          status: 302,
          headers: [header('Location', 'https://other.example.org/x')],
        ),
      );

      final response = await versola.httpClient().send(
        http.Request('GET', api),
      );

      expect(response.statusCode, 302);
      expect(response.isRedirect, isTrue);
      expect(response.headers['location'], 'https://other.example.org/x');
      expect((response as http.BaseResponseWithUrl).url, api);
      expect(host.requests, hasLength(1));
    });

    test(
      'a 304 or a 302 without Location is not reported as a redirect',
      () async {
        final (host, versola) = await setUp();
        host
          ..answers.add(ok(status: 304))
          ..answers.add(ok(status: 302));
        final client = versola.httpClient();

        expect(
          (await client.send(http.Request('GET', api))).isRedirect,
          isFalse,
        );
        expect(
          (await client.send(http.Request('GET', api))).isRedirect,
          isFalse,
        );
      },
    );

    test(
      'a closed client refuses a request without touching the host',
      () async {
        final (host, versola) = await setUp();
        final client = versola.httpClient()..close();
        await expectLater(
          client.get(api),
          throwsA(isA<http.ClientException>()),
        );
        expect(host.requests, isEmpty);
      },
    );
  });

  group('credentials', () {
    test('an Authorization header the app set is handed to native as the app wrote it; replacing it is native\'s rule', () async {
      final (host, versola) = await setUp();
      host.answers.add(ok());
      await versola.httpClient().get(
        api,
        headers: {'Authorization': 'Bearer app-made'},
      );
      expect(
        headerOf(host.requests.single, 'authorization'),
        'Bearer app-made',
      );
    });
  });

  group('errors arrive typed', () {
    VersolaErrorMessage message(
      VersolaErrorCategoryMessage category,
      String kind, {
      List<String>? acr,
      int? maxAge,
      String? origin,
    }) => VersolaErrorMessage(
      category: category,
      kind: kind,
      message: kind,
      acrValues: acr,
      maxAge: maxAge,
      origin: origin,
    );

    test('a step-up challenge is StepUpError with its acr_values and max_age, which stepUp accepts', () async {
      final (host, versola) = await setUp();
      host.answers.add(
        failure(
          message(
            VersolaErrorCategoryMessage.stepUp,
            'stepUp',
            acr: ['sensitive'],
            maxAge: 60,
          ),
        ),
      );
      StepUpError? challenge;
      try {
        await versola.httpClient().get(api);
      } on StepUpError catch (e) {
        challenge = e;
      }
      expect(challenge, isNotNull);
      expect(challenge!.acrValues, ['sensitive']);
      expect(challenge.maxAge, 60);

      host.answers.add(VersolaVoidOk());
      await versola.stepUp(challenge);
      expect(host.calls.last, 'stepUp:sensitive:60');
      expect(host.stepUpOptions.last, isNull);
    });

    test('a refused session, a nonce loop and a configuration error keep their category', () async {
      final (host, versola) = await setUp();
      host
        ..answers.add(
          failure(
            message(
              VersolaErrorCategoryMessage.reauthenticate,
              'sessionRejected',
            ),
          ),
        )
        ..answers.add(
          failure(
            message(
              VersolaErrorCategoryMessage.recoverable,
              'nonceLoop',
              origin: 'https://id.example.com',
            ),
          ),
        )
        ..answers.add(
          failure(
            message(
              VersolaErrorCategoryMessage.configuration,
              'invalidConfiguration',
            ),
          ),
        );
      final client = versola.httpClient();

      await expectLater(
        client.get(api),
        throwsA(
          isA<ReauthenticateError>().having(
            (e) => e.reason,
            'reason',
            ReauthenticateReason.sessionRejected,
          ),
        ),
      );
      await expectLater(
        client.get(api),
        throwsA(
          isA<RecoverableError>()
              .having((e) => e.cause, 'cause', RecoverableCause.nonceLoop)
              .having((e) => e.origin, 'origin', 'https://id.example.com'),
        ),
      );
      await expectLater(client.get(api), throwsA(isA<ConfigurationError>()));
    });

    test('a transport failure is a ClientException naming the class only, never an OAuthError and never the URL from native', () async {
      final (host, versola) = await setUp();
      host.answers.add(
        VersolaHttpTransportFailure(exception: 'UnknownHostException'),
      );
      await expectLater(
        versola.httpClient().get(api),
        throwsA(
          isA<http.ClientException>()
              .having(
                (e) => e.message,
                'message',
                contains('UnknownHostException'),
              )
              .having(
                (e) => e.message,
                'message',
                isNot(contains('resources/items')),
              ),
        ),
      );
      // And it is not one of ours.
      host.answers.add(VersolaHttpTransportFailure(exception: 'IOException'));
      Object? thrown;
      try {
        await versola.httpClient().get(api);
      } catch (e) {
        thrown = e;
      }
      expect(thrown, isNot(isA<OAuthError>()));
    });

    test('a channel failure is a ConfigurationError with the code and none of the message', () async {
      final (host, versola) = await setUp();
      host.answers.add(
        PlatformException(
          code: 'channel-error',
          message: 'at okhttp3.internal: Authorization: DPoP do-not-leak',
        ),
      );
      await expectLater(
        versola.httpClient().get(api),
        throwsA(
          isA<ConfigurationError>()
              .having((e) => e.text, 'text', 'bridge failure: channel-error')
              .having(
                (e) => e.toString(),
                'toString',
                isNot(contains('do-not-leak')),
              ),
        ),
      );
    });
  });

  group('composition', () {
    test('an app interceptor wrapping the client runs first, and native sees its final URL and headers', () async {
      final (host, versola) = await setUp();
      host.answers.add(ok());
      final client = _Rewriting(versola.httpClient());
      await client.get(api);
      expect(headerOf(host.requests.single, 'x-request-id'), 'r-1');
    });

    test('RetryClient around ours retries a 503 as the app chose, and native is asked each time', () async {
      final (host, versola) = await setUp();
      host
        ..answers.add(ok(status: 503))
        ..answers.add(ok(status: 200));
      final client = RetryClient(
        versola.httpClient(),
        delay: (_) => Duration.zero,
        when: (r) => r.statusCode == 503,
      );
      expect((await client.get(api)).statusCode, 200);
      expect(host.requests, hasLength(2));
    });
  });
}

class _Rewriting extends http.BaseClient {
  _Rewriting(this._inner);
  final http.Client _inner;
  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) {
    request.headers['x-request-id'] = 'r-1';
    return _inner.send(request);
  }
}
