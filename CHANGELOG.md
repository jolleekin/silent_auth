# Changelog

## 0.0.8
- Improve README.md
- Update documentation

## 0.0.7
- *BREAKING CHANGE*: This version requires Dart 2.0.0 or later
- Fixed a bug where accessing `Token.header` will throw
- Added some tests

## 0.0.6
- Fixed a bug that happens when `logOut` is called due to the new `Token` type

## 0.0.5
- refactoring: `utils.dart` was moved to `/lib` and no longer contains functions used internally
- Added class `Token`, which represents an access or ID token
- *BREAKING CHANGE*: `SilentAuth.accessToken` and `SilentAuth.idToken` are now of type `Token` rather than `String`.

## 0.0.4
- Fixed a bug in which the token renewal is not properly scheduled the first time

## 0.0.3
- Fixed a bug causing `post_logout_redirect_uri` not to be displayed in the logged-out page

## 0.0.2
- Fixed a bug causing `utils.callEndpoint` to fail when compiled to JS

## 0.0.1
- Initial version
