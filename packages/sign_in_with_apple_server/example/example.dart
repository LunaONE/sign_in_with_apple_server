import 'package:sign_in_with_apple_server/sign_in_with_apple_server.dart';

final siwa = SignInWithApple(
  config: SignInWithAppleConfiguration(
    serviceIdentifier: 'com.acme.app-service',
    bundleIdentifier: 'com.acme.app',
    redirectUri: 'https://acme.com/hooks/return-url',
    teamId: 'ABC1234567',
    keyId: '89DEFGHIJK',
    key: '-----BEGIN PRIVATE KEY---……',
  ),
);

/// A combined Sign in with Apple registration / login endpoint.
///
/// Returns a session key ("cookie") after successful authorization.
Future<String> signInEndpoint({
  required String authorizationCode,
  required String identityToken,

  /// If `true` this means the sign-in comes from an Apple native OS,
  /// in which case the bundle identifier is used, else the service ID.
  required bool useBundleIdentifier,
  required String? firstName,
  required String? lastName,
}) async {
  final verifiedIdentityToken = await siwa.verifyIdentityToken(
    identityToken,
    useBundleIdentifier: useBundleIdentifier,
    nonce: null,
  );

  // Now check whether the user is already known in the system,
  // by looking up the [verifiedIdentityToken.userId] which is Apple's
  // unique user identifer for the linked account.
  final foundUser = await findUserByAppleUserId(verifiedIdentityToken.userId);
  if (foundUser != null) {
    return createSession(foundUser.id);
  }

  // If no user was found, create a new user in your sytem.
  final refreshToken = await siwa.exchangeAuthorizationCode(
    authorizationCode,
    useBundleIdentifier: useBundleIdentifier,
  );

  final newUser = await createUser(
    appleUserId: verifiedIdentityToken.userId,
    email: verifiedIdentityToken.emailVerified == true
        ? verifiedIdentityToken.email
        : null,
    refreshToken: refreshToken.refreshToken,
    useBundleIdentifier: useBundleIdentifier, // store this for later
    firstName: firstName,
    lastName: lastName,
  );

  return createSession(newUser.id);
}
