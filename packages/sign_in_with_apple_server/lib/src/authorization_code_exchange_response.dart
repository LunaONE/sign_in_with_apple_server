/// Response value of a successful `authorizationCode` exchange.
///
/// Since the `authorizationCode` can only be used once, the receiver
/// should then store the `refreshToken` and whether the bundle or service
/// identifier was used for the request, as that information is needed for
/// subsequent usages of the refresh token.
class AuthorizationCodeExchangeResponse {
  AuthorizationCodeExchangeResponse({
    required this.accessToken,
    required this.accessTokenExpiresIn,
    required this.idToken,
    required this.refreshToken,
  });

  final String accessToken;

  final int accessTokenExpiresIn;

  final String idToken;

  /// The refresh token received in exchange for the `authorizationCode`.
  ///
  /// This can be used later to query the latest "identity token",
  /// or revoke the authorization linked to the Apple account.
  final String refreshToken;

  @override
  String toString() {
    return 'AuthorizationCodeExchangeResponse(accessToken: $accessToken, accessTokenExpiresIn: $accessTokenExpiresIn, idToken: $idToken, refreshToken: $refreshToken)';
  }
}
