library silent_auth.src.utils;

import 'dart:async';
import 'dart:convert';
import 'dart:html';
import 'dart:js';
import 'dart:typed_data';

const charset = '0123456789ABCDEFGHIJKLMNOPQRSTUVXYZabcdefghijklmnopqrstuvwxyz-._~';
const oneMinute = const Duration(minutes: 1);
const timeoutResponse = const {'error': 'timeout'};

/// Silently calls an identity server's endpoint specified by [uri] using an `iframe`.
///
/// [timeout] specifies the maximum duration allowed for this call. If [timeout]
/// passes when the request is ongoing, this function will return [timeoutResponse].
Future<Map<String, String>> callEndpoint(String uri,
    {Duration timeout = oneMinute}) async {
  IFrameElement frame;
  StreamSubscription sub;
  Timer timer;

  void done() {
    frame.remove();
    sub.cancel();
    timer.cancel();
  }

  var completer = new Completer<Map<String, String>>();

  frame = new IFrameElement()..hidden = true;
  sub = frame.onLoad.listen((_) {
    var jsLocation =
        new JsObject.fromBrowserObject(frame.contentWindow.location);
    var fragment = jsLocation['hash'].substring(1);
    var response = Uri.splitQueryString(fragment);
    done();
    if (response.containsKey('error')) {
      completer.completeError(response);
    } else {
      completer.complete(response);
    }
  });
  frame.src = uri;
  document.body.append(frame);

  timer = new Timer(timeout, () {
    done();
    completer.completeError(timeoutResponse);
  });

  return completer.future;
}

/// Decodes the payload of JWT token.
Map<String, dynamic> decodeTokenPayload(String token) {
  var encoded = token.split('.')[1];

  // Ensure the payload length is a multiple of 4.
  var r = encoded.length & 3;
  if (r > 0) encoded += '%3D' * (4 - r);

  var decoded = JSON.decode(new String.fromCharCodes(BASE64.decode(encoded)));
  return decoded;
}

/// Creates a securely random string with [length] characters in [charset].
String randomString(int length) {
  var bytes = new Uint8List(length);
  window.crypto.getRandomValues(bytes);
  var result = bytes.map((e) => charset[e % charset.length]).join();
  return result;
}
