library silent_auth;

import 'dart:async';
import 'dart:html';
import 'dart:js';

import 'utils.dart';

const oneMinute = Duration(minutes: 1);

class SilentAuth {
  /// [baseIdentityUri] should not have a trailing slash. Endpoint URIs will be
  /// constructed by appending their paths to [baseIdentityUri]. Examples:
  /// - [Authorize Endpoint][1] = [baseIdentityUri] + '/authorize'
  /// - [End Session Endpoint][2] = [baseIdentityUri] + '/endsession'
  ///
  /// - [1]: http://docs.identityserver.io/en/latest/endpoints/authorize.html
  /// - [2]: http://docs.identityserver.io/en/latest/endpoints/endsession.html
  final String baseIdentityUri;

  /// The client ID.
  final String clientId;

  /// The response type, e.g. `token`, `id_token token`, ....
  final String responseType;

  /// The login redirect URI.
  final String redirectUri;

  /// The token renewal redirect URI.
  ///
  /// This URI must belong to the application's domain. Usually, this just
  /// points to a dummy HTML file.
  final String silentRedirectUri;

  /// The scope.
  final String scope;

  /// The maximum duration allowed for the token renewal.
  final Duration timeout;

  final void Function(SilentAuth auth) _onRenew;
  final Map<String, String> _storage;
  Uri _authorizeEndpoint;
  Uri _endSessionEndpoint;
  Token _accessToken;
  Duration _expiresIn;
  DateTime _expiresAt;
  Token _idToken;
  bool _includeNonce;
  bool _initialized = false;
  Timer _renewTimer;
  Map<String, String> _authorizeParameters;
  Map<String, String> _silentAuthorizeParameters;

  /// Creates a [SilentAuth] instance.
  ///
  /// [authorizePath] and [endSessionPath] are the paths of the Authorize and
  /// End Session endpoints, respectively.
  ///
  /// [onRenew] is the callback to be invoked after each successful token
  /// renewal.
  ///
  /// [storage] will be used to persist authentication data. It is defaulted to
  /// [window.localStorage].
  ///
  /// For a description of the other parameters, please visit
  /// [Authorize Endpoint][1] and [End Session Endpoint][2].
  ///
  /// - [1]: http://docs.identityserver.io/en/latest/endpoints/authorize.html
  /// - [2]: http://docs.identityserver.io/en/latest/endpoints/endsession.html
  SilentAuth(
      {this.baseIdentityUri,
      this.clientId,
      this.redirectUri,
      this.silentRedirectUri,
      this.scope,
      this.responseType = 'id_token token',
      String authorizePath = '/authorize',
      String endSessionPath = '/endsession',
      this.timeout = oneMinute,
      void onRenew(SilentAuth auth),
      Map<String, String> storage})
      : _onRenew = onRenew,
        _storage = storage ?? window.localStorage {
    _authorizeEndpoint = Uri.parse('$baseIdentityUri$authorizePath');
    _endSessionEndpoint = Uri.parse('$baseIdentityUri$endSessionPath');
    _includeNonce = responseType.contains('id_token');
  }

  /// The access token.
  Token get accessToken => _accessToken;

  /// The date and time at which [accessToken] expires.
  DateTime get expiresAt => _expiresAt;

  /// The lifetime of the [accessToken].
  Duration get expiresIn => _expiresIn;

  /// The ID token.
  Token get idToken => _idToken;

  /// Whether [accessToken] exists and doesn't expire yet.
  bool get isAccessTokenValid =>
      _accessToken != null && _expiresAt.isAfter(_utcNow);

  /// Initializes silent authentication.
  void init() {
    if (_initialized) return;

    _initialized = true;

    _authorizeParameters = {
      'response_type': responseType,
      'redirect_uri': redirectUri,
      'client_id': clientId,
      'scope': scope,
      'state': null,
      'nonce': null,
    };
    _silentAuthorizeParameters = Map.from(_authorizeParameters)
      ..['redirect_uri'] = silentRedirectUri
      ..['prompt'] = 'none';

    _restore();

    if (window.location.hash.contains('access_token')) {
      var response = Uri.splitQueryString(window.location.hash.substring(1));
      _handleResponse(response, _authorizeParameters);
    } else if (isAccessTokenValid) {
      _scheduleTokenRenewal();
    }
  }

  /// Performs login by redirecting user to the authorize endpoint.
  void logIn() {
    _checkInitialized();

    _cancelTokenRenewal();

    var state = randomString(_keyLength);
    _authorizeParameters['state'] = state;
    _saveParam('state', state);

    if (_includeNonce) {
      var nonce = randomString(_keyLength);
      _authorizeParameters['nonce'] = nonce;
      _saveParam('nonce', nonce);
    }

    var uri = _authorizeEndpoint.replace(queryParameters: _authorizeParameters);
    window.location.href = uri.toString();
  }

  /// Performs login by redirecting user to the end session endpoint.
  void logOut() {
    _checkInitialized();

    var q = {
      'post_logout_redirect_uri': redirectUri,
      'id_token_hint': _idToken?.rawValue,
    };
    _cancelTokenRenewal();
    _clear();

    var uri = _endSessionEndpoint.replace(queryParameters: q);
    window.location.href = uri.toString();
  }

  void _cancelTokenRenewal() {
    _renewTimer?.cancel();
  }

  void _checkInitialized() {
    if (!_initialized) {
      throw StateError('SilentAuth has not been initialized.');
    }
  }

  void _clear() {
    _accessToken = null;
    _idToken = null;
    _expiresAt = null;
    _expiresIn = null;
    var keys = _storage.keys.toList();
    for (var key in keys) {
      if (key.startsWith(_namespace)) {
        _storage.remove(key);
      }
    }
  }

  void _handleError(error, [stackTrace]) {
    print('$_namespace: $error');
  }

  void _handleResponse(
      Map<String, String> response, Map<String, String> request) {
    if (response['state'] != request['state']) {
      _handleError(const {'error': 'state_unmatched'});
      return;
    }
    if (_includeNonce) {
      var token = Token(response['id_token']);
      if (token.payload['nonce'] != request['nonce']) {
        _handleError(const {'error': 'nonce_unmatched'});
        return;
      }
    }
    _saveResponse(response);
    _scheduleTokenRenewal();
    if (_onRenew != null) _onRenew(this);
  }

  void _handleSilentResponse(Map<String, String> response) =>
      _handleResponse(response, _silentAuthorizeParameters);

  String _readParam(String key) => _storage['$_namespace.$key'];

  void _renewToken() {
    _silentAuthorizeParameters['state'] = randomString(_keyLength);
    if (_includeNonce) {
      _silentAuthorizeParameters['nonce'] = randomString(_keyLength);
    }
    var uri =
        _authorizeEndpoint.replace(queryParameters: _silentAuthorizeParameters);
    _callEndpoint(uri.toString(), timeout: timeout)
        .then(_handleSilentResponse)
        .catchError(_handleError);
  }

  void _restore() {
    // Request.

    _authorizeParameters['state'] = _readParam('state');
    if (_includeNonce) {
      _authorizeParameters['nonce'] = _readParam('nonce');
    }

    // Response.

    var value = _readParam('access_token');
    if (value != null) {
      _accessToken = Token(value);

      value = _readParam('id_token');
      if (value != null) _idToken = Token(value);

      value = _readParam('expires_at');
      if (value != null) _expiresAt = DateTime.parse(value);

      value = _readParam('expires_in');
      if (value != null) _expiresIn = _parseDuration(value);
    }
  }

  String _saveParam(String key, String value) =>
      _storage['$_namespace.$key'] = value;

  void _saveResponse(Map<String, String> response) {
    var value = _saveParam('access_token', response['access_token']);
    _accessToken = value != null ? Token(value) : null;

    value = _saveParam('id_token', response['id_token']);
    _idToken = value != null ? Token(value) : null;

    value = _saveParam('expires_in', response['expires_in']);
    _expiresIn = _parseDuration(value);

    _expiresAt = _utcNow.add(_expiresIn);
    _saveParam('expires_at', _expiresAt.toString());
  }

  void _scheduleTokenRenewal() {
    if (!_supportsIFrame) return;

    // We don't want to wait for the access token to expire, otherwise the user
    // experience will be affected.
    var duration = _expiresAt.difference(_utcNow) - timeout;
    _renewTimer = Timer(duration, _renewToken);
  }
}

/// A class that represents an access or ID token.
/// See [JSON Web Tokens](https://jwt.io/)
class Token {
  final String rawValue;

  Map<String, dynamic> _header;
  Map<String, dynamic> _payload;
  String _signature;
  final int _i0;
  final int _i1;

  Token(this.rawValue)
      : _i0 = rawValue.indexOf('.'),
        _i1 = rawValue.lastIndexOf('.');

  Map<String, dynamic> get header {
    _header ??= base64ToJson(rawValue.substring(0, _i0));
    return _header;
  }

  Map<String, dynamic> get payload {
    _payload ??= base64ToJson(rawValue.substring(_i0 + 1, _i1));
    return _payload;
  }

  String get signature {
    _signature ??= rawValue.substring(_i1 + 1);
    return _signature;
  }

  String toString() => rawValue;
}

const _keyLength = 32;
const _namespace = 'silent_auth';
const _timeoutResponse = {'error': 'timeout'};

final bool _supportsIFrame = (() {
  try {
    var e = JsObject.fromBrowserObject(IFrameElement());
    return e.hasProperty('src');
  } catch (_) {
    return false;
  }
})();

DateTime get _utcNow => DateTime.now().toUtc();

/// Silently calls an identity server's endpoint specified by [uri].
///
/// [timeout] specifies the maximum duration allowed for this call.
/// If [timeout] passes when the request is ongoing, this function will return
/// [_timeoutResponse].
///
/// For any other error [:e:], this function will return the following [Map]
///     {
///       'error': 'other',
///       'original': e
///     }
Future<Map<String, String>> _callEndpoint(String uri,
    {Duration timeout = oneMinute}) {
  IFrameElement frame;
  StreamSubscription sub;
  Timer timer;

  void done() {
    frame.remove();
    sub.cancel();
    timer.cancel();
  }

  var completer = Completer<Map<String, String>>();

  frame = IFrameElement()..hidden = true;
  sub = frame.onLoad.listen((_) {
    try {
      var jsFrame = JsObject.fromBrowserObject(frame);
      var fragment = jsFrame['contentWindow']['location']['hash'].substring(1);
      var response = Uri.splitQueryString(fragment);
      if (response.containsKey('error')) {
        completer.completeError(response);
      } else {
        completer.complete(response);
      }
    } catch (e, s) {
      completer.completeError({'error': 'other', 'original': e}, s);
    } finally {
      done();
    }
  });
  frame.src = uri;
  document.body.append(frame);

  timer = Timer(timeout, () {
    done();
    completer.completeError(_timeoutResponse);
  });

  return completer.future;
}

/// Only supports seconds.
Duration _parseDuration(String input) => Duration(seconds: int.parse(input));
