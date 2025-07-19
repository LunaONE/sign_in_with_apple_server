/// The contents of a parsed identity token.
///
/// The real user status is only set on the initial login.
class IdentityToken {
  IdentityToken({
    required this.userId,
    required this.email,
    required this.emailVerified,
    required this.isPrivateEmail,
    required this.realUserStatus,
    required this.nonce,
    required this.nonceSupported,
  });

  final String userId;

  final String? email;

  final bool? emailVerified;

  final bool? isPrivateEmail;

  /// 0 = Unsupported
  /// 1 = Unknown
  /// 2 = LikelyReal
  final int? realUserStatus;

  final String? nonce;

  final bool? nonceSupported;

  @override
  String toString() {
    return 'IdentityToken(userId: $userId, email: $email, emailVerified: $emailVerified, isPrivateEmail: $isPrivateEmail, realUserStatus: $realUserStatus, nonce: $nonce, nonceSupported: $nonceSupported)';
  }
}
