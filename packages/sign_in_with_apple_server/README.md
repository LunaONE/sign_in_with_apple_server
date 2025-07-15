Utilites to build a backend supporting _Sign in with Apple_ in Dart.

Supports:
- Validating identity tokens (to get a trusted user ID and, optionally, email address)
- Converting the authorization code into a refresh token (to continually check on the account's status)
- Revoking the user's authorization

To implement the client-side in Flutter, [sign_in_with_apple](https://pub.dev/packages/sign_in_with_apple) is recommended.
