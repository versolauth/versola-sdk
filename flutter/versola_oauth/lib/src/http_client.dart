import 'dart:async';

import 'package:http/http.dart' as http;

import 'mapping.dart';
import 'messages.g.dart' as bridge;

/// The `package:http` face of the native authenticated client (`spec/oauth-sdk-api.md`
/// section 10). Dart describes the request and receives the response; the token, the DPoP key
/// and its proofs, the refresh and the origin allow-list never leave native code, so nothing in
/// this class can mint a proof or see a token (`.claude/rules/flutter.md`, "What crosses the
/// bridge").
///
/// A [http.BaseClient] so an app composes it the ordinary way: its own `BaseClient`, a
/// `package:http/retry.dart` `RetryClient` or an `http_interceptor` wrapper takes this as the
/// *inner* client. That order is not a style choice: the DPoP proof is bound to the final method
/// and URL, so the authentication step must run after every app-side rewrite.
final class AuthenticatedHttpClient extends http.BaseClient {
  AuthenticatedHttpClient(this._host, this._handle, Set<String>? origins)
    : _origins = origins == null ? null : List.unmodifiable(origins);

  final bridge.OAuthHostApi _host;
  final String _handle;

  /// Null: the configuration's `protectedOrigins`, decided natively. An empty list is a request
  /// for no origins, which native refuses with `invalidConfiguration` before sending anything.
  final List<String>? _origins;
  bool _closed = false;

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    if (_closed) {
      // The wording and the type `package:http`'s own clients use for a closed client.
      throw http.ClientException(
        'HTTP request failed. Client is already closed.',
        request.url,
      );
    }
    // The body is buffered here and again natively: the bridge carries bytes, not a stream.
    final body = await request.finalize().toBytes();
    final result = await guarded(
      () => _host.httpRequest(
        _handle,
        bridge.HttpRequestMessage(
          method: request.method,
          url: request.url.toString(),
          headers: [
            for (final MapEntry(:key, :value) in request.headers.entries)
              bridge.HttpHeaderMessage(name: key, value: value),
          ],
          body: body.isEmpty ? null : body,
          origins: _origins,
        ),
      ),
    );
    switch (result) {
      case bridge.HttpOk(:final response):
        return _response(request, response);
      case bridge.HttpFailure(:final error):
        throw errorFromMessage(error);
      case bridge.HttpTransportFailure(:final exception):
        throw http.ClientException(
          'HTTP request failed: $exception',
          request.url,
        );
    }
  }

  @override
  void close() {
    _closed = true;
  }
}

/// A redirect status with a `Location`, the shape `dart:io`'s `isRedirect` reports. Native never
/// follows one, so this is what tells the app that it is looking at a redirect it must decide
/// about (`spec/oauth-sdk-api.md` section 10).
const _redirectStatuses = {301, 302, 303, 307, 308};

http.StreamedResponse _response(
  http.BaseRequest request,
  bridge.HttpResponseMessage message,
) {
  // `package:http`'s convention (BaseResponse.headers): lower-case names, repeated names joined
  // with a comma, which `headersSplitValues` splits again. Android reports every value of a
  // repeated header apart; iOS's URLSession reports them already joined (conformance/README.md).
  final values = <String, List<String>>{};
  for (final header in message.headers) {
    values
        .putIfAbsent(header.name.toLowerCase(), () => <String>[])
        .add(header.value.trim());
  }
  final headers = {
    for (final MapEntry(:key, :value) in values.entries) key: value.join(','),
  };
  return _BufferedResponse(
    Stream<List<int>>.value(message.body),
    message.status,
    url: request.url,
    // The length of what was buffered, which is what a reader of the stream will count; a
    // Content-Length header may describe the encoded body the platform has already decoded.
    contentLength: message.body.length,
    request: request,
    headers: headers,
    isRedirect:
        _redirectStatuses.contains(message.status) &&
        headers.containsKey('location'),
    reasonPhrase: message.reasonPhrase,
  );
}

/// A response whose body is already in memory, with the `url` `package:http` 1.x offers through
/// [http.BaseResponseWithUrl]: no redirect is followed, so it is the request's.
final class _BufferedResponse extends http.StreamedResponse
    implements http.BaseResponseWithUrl {
  _BufferedResponse(
    super.stream,
    super.statusCode, {
    required this.url,
    required super.contentLength,
    required super.request,
    required super.headers,
    required super.isRedirect,
    required super.reasonPhrase,
  });

  @override
  final Uri url;
}
