/// The result of a successful refresh token validation response.
///
/// Contains the latest "identity token".
class RefreshTokenValidationResponse {
  RefreshTokenValidationResponse({
    required this.accessToken,
    required this.accessTokenExpiresIn,
    required this.idToken,
  });

  final String accessToken;

  final int accessTokenExpiresIn;

  /// The latest "identity token".
  ///
  /// For sign-ups that included the `email` scope, this will include the current
  /// email address for the user.
  final String idToken;

  @override
  String toString() {
    return 'RefreshTokenValidationResponse(accessToken: $accessToken, accessTokenExpiresIn: $accessTokenExpiresIn, idToken: $idToken)';
  }
}
