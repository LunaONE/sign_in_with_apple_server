/// Configuration for the Sign in with Apple server class.
class SignInWithAppleConfiguration {
  SignInWithAppleConfiguration({
    required this.serviceIdentifier,
    required this.bundleIdentifier,
    required this.redirectUri,
    required this.teamId,
    required this.keyId,
    required this.key,
  });

  /// The bundle identifier (app ID).
  final String bundleIdentifier;

  /// The service ID, used logins via web or web-views/in-app browser (e.g. on Android).
  final String serviceIdentifier;

  /// The configured redirect URLs where non-pop-up web logins return to.
  final String redirectUri;

  /// The team ID of the app's parent Apple Developer account.
  final String teamId;

  /// ID of the service key
  final String keyId;

  /// The private key created by Apple for your app.
  final String key;
}
