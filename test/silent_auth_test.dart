import 'dart:html';

import 'package:silent_auth/silent_auth.dart';
import 'package:test/test.dart';

/// Run this test by
/// 1. `pub global run webdev serve test:11111`
/// 2. Open a browser and navigate to `http://localhost:11111`
main() {
  test('Token', () {
    const expectedHeader = {
      "alg": "HS256",
      "typ": "JWT",
    };
    const expectedPayload = {
      "sub": "1234567890",
      "name": "John Doe",
      "iat": 1516239022,
    };
    const expectedSignature = 'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

    final token = Token('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.'
        'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.'
        '$expectedSignature');

    expect(token.header, equals(expectedHeader));
    expect(token.payload, equals(expectedPayload));
    expect(token.signature, equals(expectedSignature));
  });

  test('SilentAuth', () {
    /// Sample response using https://demo.identityserver.io/connect/authorize?client_id=implicit&scope=openid+api&response_type=token+id_token&redirect_uri=https%3A%2F%2Fnotused&nonce=12345&state=67890
    final response = 'id_token=eyJhbGciOiJSUzI1NiIsImtpZCI6ImEwN2FiY2M5NTM0NTlhODE5NWMwZTZkMjBhODQ1NWVjIiwidHlwIjoiSldUIn0.eyJuYmYiOjE1MzY1MTQyNDYsImV4cCI6MTUzNjUxNDU0NiwiaXNzIjoiaHR0cHM6Ly9kZW1vLmlkZW50aXR5c2VydmVyLmlvIiwiYXVkIjoiaW1wbGljaXQiLCJub25jZSI6IjEyMzQ1IiwiaWF0IjoxNTM2NTE0MjQ2LCJhdF9oYXNoIjoialRjbC1ZQW9RTlo1cGY0d3V2bmJUQSIsInNpZCI6IjIyYTYzMzZhNmExZWNjNzI3NmQ2MzI3ZjIwMTM5Nzc2Iiwic3ViIjoiODg0MjExMTMiLCJhdXRoX3RpbWUiOjE1MzY1MTM0MDgsImlkcCI6ImxvY2FsIiwiYW1yIjpbInB3ZCJdfQ.G5tI93yLqxq8DKwo9s9vMVHpKmtVsUdz_YRu5TOp9qpR6HmRCBg7CqA97N-8NNZ19WL1xzZcgKyF_3DpUGpog99tKNfryDAOtN3Is4MefdNdiNGE12EF2dom8S7XcSqiIkLrVBVZPYnnMDrBPLtEQcAbFhkvMW0qz0ck55v-bV614aqvSXiHgN9aCa9YCC3H0FM344-pLFQRGncQ5t-RQAyV72Y16oKeyg3m0k4wcaVddevuv7QyDnCv-FzgbkqR6kLOOtauwtBP14eBCl4lw8-Y9yGDJo6acRnH4fTVUYucG7olM1VXFXK1A9suRAGkYlKbIzZmr_WapssHwGUxVw&'
        'access_token=eyJhbGciOiJSUzI1NiIsImtpZCI6ImEwN2FiY2M5NTM0NTlhODE5NWMwZTZkMjBhODQ1NWVjIiwidHlwIjoiSldUIn0.eyJuYmYiOjE1MzY1MTQyNDYsImV4cCI6MTUzNjUxNzg0NiwiaXNzIjoiaHR0cHM6Ly9kZW1vLmlkZW50aXR5c2VydmVyLmlvIiwiYXVkIjpbImh0dHBzOi8vZGVtby5pZGVudGl0eXNlcnZlci5pby9yZXNvdXJjZXMiLCJhcGkiXSwiY2xpZW50X2lkIjoiaW1wbGljaXQiLCJzdWIiOiI4ODQyMTExMyIsImF1dGhfdGltZSI6MTUzNjUxMzQwOCwiaWRwIjoibG9jYWwiLCJzY29wZSI6WyJvcGVuaWQiLCJhcGkiXSwiYW1yIjpbInB3ZCJdfQ.F6nT2B8XLG2thbcZOnxwe3942nCd2C5jdpzK2V2qfuicTgPRoY6DuKB_NPcR0vDZElSgg6L_hJBRGGrPj_lToz2pjt6dKY1WNosCVxZskOjybUxOidsBr-mC8M2szy91UpJQ5lz4oEdX8z0tIJVhotqP62r2h-QHw-Rpv1yXbCBsqB0zu6y5GcmK4QszH2SAWLPb1ZOA87O-MpCayKndkVoAbMVP-pW3aRQ4gkM4roXT9oJmIc0goVMMvI6p3FyN2qRJwRo_zwyY7Ii3K3YoppR2QqFXVtYeYB0AVKjl2bG9zgj1f9knyDmWzqqu1Cat0ecuYYMHLekZqXvl4Itcmw&'
        'token_type=Bearer&'
        'expires_in=3600&'
        'scope=openid%20api&'
        'nonce=12345&'
        'state=67890&'
        'session_state=ubJujZ_w_oVgfHBkwjhNw8S0AjvZdt0WQoYdtvPGG4I.ce53c19c8779c990af828a838d53d7c5';
    final queryParameters = Uri.splitQueryString(response);

    window.location.hash = response;
    window.localStorage
      ..['silent_auth.nonce'] = queryParameters['nonce']
      ..['silent_auth.state'] = queryParameters['state'];

    final auth = SilentAuth(
      baseIdentityUri: '',
      redirectUri: '',
      silentRedirectUri: '',
    );

    auth.init();

    expect(auth.isAccessTokenValid, equals(true));
    expect(auth.accessToken.rawValue, equals(queryParameters['access_token']));
    expect(auth.idToken.rawValue, equals(queryParameters['id_token']));
  });
}
