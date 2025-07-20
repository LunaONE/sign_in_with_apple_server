Utilites to build a backend supporting _Sign in with Apple_ in Dart.

Supports:
- Validating identity tokens (to get a trusted user ID and, optionally, email address)
- Exchanging the authorization code for a refresh token
- Checking the user's current account status with their refresh token
- Revoking the user's authorization
- Handle incoming server-to-server notification from Apple (via web hook)

To implement the client-side in Flutter, [sign_in_with_apple](https://pub.dev/packages/sign_in_with_apple) is recommended.

For ready-made server handlers for the [Relic](https://pub.dev/packages/relic) Dart webserver see [sign_in_with_apple_server_relic](https://pub.dev/packages/sign_in_with_apple_server_relic).