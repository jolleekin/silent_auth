# silent_auth

`silent_auth` is a package that enables seamless user experience for single page web
applications using OAuth 2.0 - OpenID Connect with the implicit flow.
More information can be found at [Silent Authentication][silent_auth].
In summary, this package
- Performs login by redirecting user to an identity server's authorize endpoint
- Performs logout by redirecting user to an identity server's end session endpoint
- Periodically renews access/ID tokens in the background using `iframe`

## Usage

This package is usually used together with an idle tracking library/package such as [idle_tracker][idle_tracker].

    import 'package:silent_auth/silent_auth.dart';
    import 'package:idle_tracker/idle_tracker.dart';

    final silentAuth = new SilentAuth(
        baseIdentityUri: 'https://your-identity-server.com/connect',
        clientId: 'admin',
        scope: 'openid api',
        redirectUri: 'http://localhost:12345/index.html'
        silentRedirectUri: 'http://localhost:12345/silent_auth.html',
        onRenew: (auth) => requestHeaders['Authorization'] = 'Bearer ${auth.accessToken}');
    
    // Request headers for making API calls.
    final requestHeaders = {
      'Accept': 'application/json',
      'Content-Type': 'application/json; charset=UTF-8',
    };
      
    void logIn() {
      // Pre-login tasks may be done here.
      
      silentAuth.logIn();
    }
    
    void logOut() {
        // Pre-logout tasks may be done here.
        
        silentAuth.logOut();
    }
    
    void loadData() {
        // Make some API call using [requestHeaders].
    }
        
    void main() {
      // Initializes silent authentication.
      silentAuth.init();
      
      // If the access token doesn't exist or has expired, redirect user to the login page.
      if (!silentAuth.isAccessTokenValid) {
        logIn();
        return;
      }
      
      // Set up an idle tracker to automatically log the user out after 30
      // minutes of inactivity.
      new IdleTracker(
          timeout: const Duration(minutes: 30),
          startsAsIdle: true,
          onIdle: logOut)
        ..start();
      
      loadData();
    }

## Features and bugs

Please file feature requests and bugs at the [issue tracker][issue_tracker].

[silent_auth]: https://auth0.com/docs/api-auth/tutorials/silent-authentication
[issue_tracker]: https://github.com/jolleekin/silent_auth/issues
[idle_tracker]: https://pub.dartlang.org/packages/idle_tracker
