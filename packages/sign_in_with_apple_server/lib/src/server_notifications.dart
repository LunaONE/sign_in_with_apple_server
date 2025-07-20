/// Parent class of known Apple server-to-server notification messages.
sealed class AppleServerNotification {}

/// Notification class for when the email of a user account has been disabled.
final class AppleServerNotificationEmailDisabled
    implements AppleServerNotification {
  AppleServerNotificationEmailDisabled({
    required this.userIdentifier,
    required this.email,
  });

  final String userIdentifier;

  final String email;
}

/// Notification class for when the email of a user account has been enabled.
final class AppleServerNotificationEmailEnabled
    implements AppleServerNotification {
  AppleServerNotificationEmailEnabled({
    required this.userIdentifier,
    required this.email,
  });

  final String userIdentifier;

  final String email;
}

/// Notification class for when the user revoked the app's authorization.
///
/// After receiving this, the next sign-in via Apple would act as a registration,
/// where the user has to specify the email and name anew (if requested).
final class AppleServerNotificationConsentRevoked
    implements AppleServerNotification {
  AppleServerNotificationConsentRevoked({
    required this.userIdentifier,
  });

  final String userIdentifier;
}

/// Notification class for when the user deleted their Apple account.
final class AppleServerNotificationAccountDelete
    implements AppleServerNotification {
  AppleServerNotificationAccountDelete({
    required this.userIdentifier,
  });

  final String userIdentifier;
}
