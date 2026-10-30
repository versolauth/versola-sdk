import 'dart:convert';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/retry.dart';
import 'package:versola_oauth/src/messages.g.dart';
import 'package:versola_oauth/versola_oauth.dart';

import 'client_test.dart' show FakeHost, created;

/// The `package:http` face of the native authenticated client, against a scripted bridge. These
/// prove the request and response mapping, the error mapping and how an app composes the client;
/// that the token is attached, refreshed and replayed is the native tiers' (`testing.md`).
HttpOk ok({
  int status = 200,
  String? reason = 'OK',
  List<HttpHeaderMessage> headers = const [],
  List<int> body = const [],
}) => HttpOk(
  response: HttpResponseMessage(
    status: status,
    reasonPhrase: reason,
    headers: headers,
    body: Uint8List.fromList(body),
  ),
);

HttpHeaderMessage header(String name, String value) =>
    HttpHeaderMessage(name: name, value: value);

HttpFailure failure(ErrorMessage error) => HttpFailure(error: error);

final api = Uri.https('api.example.com', '/items', {'page': '2'});

Future<(FakeHost, OAuthClient)> setUp() async {
  final host = FakeHost();
  return (host, await created(host));
}

String headerOf(HttpRequestMessage r, String name) => r.headers
    .where((h) => h.name.toLowerCase() == name.toLowerCase())
    .map((h) => h.value)
    .join('|');

void main() {
  group('request and response mapping', () {
    test('a request crosses as method, URL, headers and bytes, and the response comes back whole', () async {
      final (host, oauth) = await setUp();
      host.answers.add(
        ok(
          status: 201,
          reason: 'Created',
          headers: [header('Content-Type', 'application/json')],
          body: utf8.encode('{"id":1}'),
        ),
      );

      final response = await oauth.httpClient().post(
        api,
        headers: {'X-Trace': 'abc'},
        body: utf8.encode('payload'),
      );

      final sent = host.requests.single;
      expect(sent.method, 'POST');
      expect(sent.url, 'https://api.example.com/items?page=2');
      expect(headerOf(sent, 'x-trace'), 'abc');
      expect(utf8.decode(sent.body!), 'payload');
      expect(sent.origins, isNull, reason: 'null means the configured origins');
      expect(response.statusCode, 201);
      expect(response.reasonPhrase, 'Created');
      expect(response.body, '{"id":1}');
      expect(response.headers['content-type'], 'application/json');
      expect(response.contentLength, 8);
    });

    test(
      'a request without a body sends none, and a streamed body is collected',
      () async {
        final (host, oauth) = await setUp();
        host
          ..answers.add(ok())
          ..answers.add(ok());
        final client = oauth.httpClient();

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
      },
    );

    test('a repeated response header keeps every value, joined as package:http joins them', () async {
      final (host, oauth) = await setUp();
      host.answers.add(
        ok(
          status: 401,
          headers: [
            header('WWW-Authenticate', 'Bearer realm="a"'),
            header('www-authenticate', 'DPoP algs="ES256"'),
            header('Set-Cookie', 'a=1; Path=/'),
            header('Set-Cookie', 'b=2; Path=/'),
          ],
        ),
      );

      final response = await oauth.httpClient().get(api);

      expect(response.headersSplitValues['www-authenticate'], [
        'Bearer realm="a"',
        'DPoP algs="ES256"',
      ]);
      expect(response.headersSplitValues['set-cookie'], [
        'a=1; Path=/',
        'b=2; Path=/',
      ]);
    });

    test(
      'a 429 and a 503 are the response, with Retry-After, not an error',
      () async {
        final (host, oauth) = await setUp();
        host
          ..answers.add(ok(status: 429, headers: [header('Retry-After', '7')]))
          ..answers.add(ok(status: 503, headers: [header('Retry-After', '1')]));
        final client = oauth.httpClient();

        final limited = await client.get(api);
        final unavailable = await client.get(api);

        expect(limited.statusCode, 429);
        expect(limited.headers['retry-after'], '7');
        expect(unavailable.statusCode, 503);
        expect(unavailable.headers['retry-after'], '1');
        expect(
          host.requests,
          hasLength(2),
          reason: 'nothing is repeated on a status',
        );
      },
    );

    test('a redirect is returned as one, with its Location, and the request says nothing about following', () async {
      final (host, oauth) = await setUp();
      host.answers.add(
        ok(
          status: 302,
          headers: [header('Location', 'https://other.example.org/x')],
        ),
      );
      final request = http.Request(
        'GET',
        api,
      ); // followRedirects defaults to true

      final response = await oauth.httpClient().send(request);

      expect(response.statusCode, 302);
      expect(response.isRedirect, isTrue);
      expect(response.headers['location'], 'https://other.example.org/x');
      expect(response, isA<http.BaseResponseWithUrl>());
      expect((response as http.BaseResponseWithUrl).url, api);
      expect(
        host.requests,
        hasLength(1),
        reason: 'the Dart side follows nothing either',
      );
    });

    test(
      'a 304 or a 302 without Location is not reported as a redirect',
      () async {
        final (host, oauth) = await setUp();
        host
          ..answers.add(ok(status: 304))
          ..answers.add(ok(status: 302));
        final client = oauth.httpClient();

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
      'origins are passed to native as given, an empty set included',
      () async {
        final (host, oauth) = await setUp();
        host
          ..answers.add(ok())
          ..answers.add(
            failure(
              ErrorMessage(
                category: ErrorCategoryMessage.configuration,
                kind: 'invalidConfiguration',
                message: 'configuration: InvalidConfiguration',
                detail: 'at least one protected origin is required',
              ),
            ),
          );

        await oauth.httpClient(origins: {'https://api.example.com'}).get(api);
        await expectLater(
          oauth.httpClient(origins: {}).get(api),
          throwsA(
            isA<ConfigurationError>().having(
              (e) => e.detail,
              'detail',
              ConfigurationDetail.invalidConfiguration,
            ),
          ),
        );

        expect(host.requests[0].origins, ['https://api.example.com']);
        expect(
          host.requests[1].origins,
          isEmpty,
          reason: 'empty is not "use the configured ones"',
        );
      },
    );
  });

  group('credentials', () {
    test(
      'Dart never asks for the token: the only call is the request',
      () async {
        final (host, oauth) = await setUp();
        host.answers.add(ok());

        await oauth.httpClient().get(api);

        expect(host.calls, ['create:app', 'httpRequest']);
      },
    );

    test('an Authorization header the app set is handed to native as the app wrote it; replacing it is native\'s rule', () async {
      final (host, oauth) = await setUp();
      host.answers.add(ok());

      await oauth.httpClient().get(
        api,
        headers: {'Authorization': 'Bearer app-supplied', 'DPoP': 'forged'},
      );

      // Dart decides nothing about it (flutter.md: no protocol logic here). That the SDK's own
      // value replaces both on a protected origin is proven natively, in scenario 32's bridge test.
      expect(
        headerOf(host.requests.single, 'authorization'),
        'Bearer app-supplied',
      );
      expect(headerOf(host.requests.single, 'dpop'), 'forged');
    });
  });

  group('errors arrive typed', () {
    Future<Object?> thrownBy(
      FakeHost host,
      OAuthClient oauth,
      Object answer,
    ) async {
      host.answers.add(answer);
      try {
        await oauth.httpClient().get(api);
      } on Object catch (e) {
        return e;
      }
      return null;
    }

    test('a step-up challenge is StepUpError with its acr_values and max_age, which stepUp accepts', () async {
      final (host, oauth) = await setUp();

      final error = await thrownBy(
        host,
        oauth,
        failure(
          ErrorMessage(
            category: ErrorCategoryMessage.stepUp,
            kind: 'stepUp',
            message: 'step up',
            acrValues: ['urn:example:mfa'],
            maxAge: 300,
          ),
        ),
      );

      expect(error, isA<StepUpError>());
      final challenge = error! as StepUpError;
      expect(challenge.acrValues, ['urn:example:mfa']);
      expect(challenge.maxAge, 300);
      host.answers.add(VoidOk());
      await oauth.stepUp(challenge);
      expect(host.calls.last, 'stepUp:urn:example:mfa:300');
    });

    test('a refused session, a nonce loop and a configuration error keep their category', () async {
      final (host, oauth) = await setUp();

      final refused = await thrownBy(
        host,
        oauth,
        failure(
          ErrorMessage(
            category: ErrorCategoryMessage.reauthenticate,
            kind: 'sessionRejected',
            message: 'reauthenticate: SessionRejected',
          ),
        ),
      );
      final loop = await thrownBy(
        host,
        oauth,
        failure(
          ErrorMessage(
            category: ErrorCategoryMessage.recoverable,
            kind: 'nonceLoop',
            message: 'recoverable: NonceLoop',
            origin: 'https://api.example.com',
          ),
        ),
      );

      expect(refused, isA<ReauthenticateError>());
      expect(
        (refused! as ReauthenticateError).reason,
        ReauthenticateReason.sessionRejected,
      );
      expect(loop, isA<RecoverableError>());
      expect((loop! as RecoverableError).cause, RecoverableCause.nonceLoop);
    });

    test('a transport failure is a ClientException naming the class only, never an OAuthError', () async {
      final (host, oauth) = await setUp();

      final error = await thrownBy(
        host,
        oauth,
        HttpTransportFailure(exception: 'UnknownHostException'),
      );

      expect(error, isA<http.ClientException>());
      expect(error, isNot(isA<OAuthError>()));
      expect((error! as http.ClientException).uri, api);
      expect(error.toString(), contains('UnknownHostException'));
    });

    test('a channel failure is a ConfigurationError with the code and none of the message', () async {
      final (host, oauth) = await setUp();

      final error = await thrownBy(
        host,
        oauth,
        PlatformException(
          code: 'channel-error',
          message: 'Bearer secret-token',
        ),
      );

      expect(error, isA<ConfigurationError>());
      expect(error.toString(), contains('channel-error'));
      expect(error.toString(), isNot(contains('secret-token')));
    });
  });

  group('composition', () {
    test('an app interceptor wrapping the client runs first, and native sees its final URL and headers', () async {
      final (host, oauth) = await setUp();
      host.answers.add(ok());
      final client = _Rewriting(
        oauth.httpClient(),
        (request) => http.Request(
          request.method,
          Uri.https('api.example.com', '/v2/items'),
        )..headers.addAll({...request.headers, 'x-request-id': 'r-1'}),
      );

      await client.get(api, headers: {'accept': 'application/json'});

      final sent = host.requests.single;
      expect(
        sent.url,
        'https://api.example.com/v2/items',
        reason: 'the DPoP proof is minted over this one',
      );
      expect(headerOf(sent, 'x-request-id'), 'r-1');
      expect(headerOf(sent, 'accept'), 'application/json');
    });

    test('an app interceptor can transform the response', () async {
      final (host, oauth) = await setUp();
      host.answers.add(ok(body: utf8.encode('{"a":1}')));
      final client = _Transforming(oauth.httpClient());

      final response = await client.get(api);

      expect(response.body, '{"a":1}!');
    });

    test('RetryClient around ours retries a 503 as the app chose, and native is asked each time', () async {
      final (host, oauth) = await setUp();
      host
        ..answers.add(ok(status: 503))
        ..answers.add(ok(status: 200));
      final client = RetryClient(
        oauth.httpClient(),
        retries: 1,
        delay: (_) => Duration.zero,
      );

      final response = await client.get(api);

      expect(response.statusCode, 200);
      expect(host.requests, hasLength(2));
    });

    test('a StepUpError passes through a wrapper unchanged', () async {
      final (host, oauth) = await setUp();
      host.answers.add(
        failure(
          ErrorMessage(
            category: ErrorCategoryMessage.stepUp,
            kind: 'stepUp',
            message: 'step up',
            acrValues: ['mfa'],
          ),
        ),
      );
      final client = RetryClient(
        oauth.httpClient(),
        retries: 3,
        delay: (_) => Duration.zero,
      );

      await expectLater(client.get(api), throwsA(isA<StepUpError>()));
      expect(
        host.requests,
        hasLength(1),
        reason: 'RetryClient retries statuses, not errors',
      );
    });

    test(
      'a closed client refuses with ClientException and sends nothing',
      () async {
        final (host, oauth) = await setUp();
        final client = oauth.httpClient()..close();

        await expectLater(
          client.get(api),
          throwsA(isA<http.ClientException>()),
        );
        expect(host.requests, isEmpty);
      },
    );
  });
}

class _Rewriting extends http.BaseClient {
  _Rewriting(this._inner, this._rewrite);
  final http.Client _inner;
  final http.BaseRequest Function(http.BaseRequest) _rewrite;

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) =>
      _inner.send(_rewrite(request));
}

class _Transforming extends http.BaseClient {
  _Transforming(this._inner);
  final http.Client _inner;

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    final response = await _inner.send(request);
    final body = utf8.encode('${await response.stream.bytesToString()}!');
    return http.StreamedResponse(
      Stream.value(body),
      response.statusCode,
      headers: response.headers,
      request: request,
    );
  }
}
