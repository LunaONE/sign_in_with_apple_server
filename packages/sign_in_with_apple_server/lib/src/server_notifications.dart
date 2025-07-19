/// Parent class of known Apple server-to-server notification messages.
sealed class AppleServerNotification {}

/// Notification class
final class AppleServerNotificationEmailDisabled
    implements AppleServerNotification {
  AppleServerNotificationEmailDisabled({
    required this.userIdentifier,
    required this.email,
  });

  final String userIdentifier;

  final String email;
}

final class AppleServerNotificationEmailEnabled
    implements AppleServerNotification {
  AppleServerNotificationEmailEnabled({
    required this.userIdentifier,
    required this.email,
  });

  final String userIdentifier;

  final String email;
}

final class AppleServerNotificationConsentRevoked
    implements AppleServerNotification {
  AppleServerNotificationConsentRevoked({
    required this.userIdentifier,
  });

  final String userIdentifier;
}

final class AppleServerNotificationAccountDelete
    implements AppleServerNotification {
  AppleServerNotificationAccountDelete({
    required this.userIdentifier,
  });

  final String userIdentifier;
}
