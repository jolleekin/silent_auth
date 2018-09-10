library silent_auth.utils;

import 'dart:convert';
import 'dart:html';
import 'dart:typed_data';

const defaultCharset =
    '0123456789ABCDEFGHIJKLMNOPQRSTUVXYZabcdefghijklmnopqrstuvwxyz-._~';

/// Decodes a base64 string into a JSON map.
Map<String, dynamic> base64ToJson(String input) {
  // Ensure the input length is a multiple of 4.
  var r = input.length & 3;
  if (r > 0) input += '%3D' * (4 - r);

  var json = jsonDecode(String.fromCharCodes(base64Decode(input)));
  return json;
}

/// Creates a securely random string with [length] characters in [charset].
String randomString(int length, {String charset = defaultCharset}) {
  var bytes = Uint8List(length);
  window.crypto.getRandomValues(bytes);
  var result = bytes.map((e) => charset[e % charset.length]).join();
  return result;
}
