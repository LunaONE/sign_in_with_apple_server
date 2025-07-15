import 'dart:io';

import 'package:clock/clock.dart';
import 'package:sign_in_with_apple_server/sign_in_with_apple_server.dart';
import 'package:test/test.dart';

void main() {
  final siwa = SignInWithApple(
    config: SignInWithAppleConfiguration(
      serviceIdentifier: Platform.environment['SERVICE_ID']!,
      bundleIdentifier: Platform.environment['BUNDLE_IDENTIFIER']!,
      redirectUri: Platform.environment['REDIRECT_URI']!,
      teamId: Platform.environment['TEAM_ID']!,
      keyId: Platform.environment['KEY_ID']!,
      key: ECPrivateKey(
        Platform.environment['KEY_CONTENT'] ??
            File(Platform.environment['KEY_FILE_PATH']!).readAsStringSync(),
      ),
    ),
    keySource: () async =>
        File('./test/apple_auth_keys_2025-07-13.json').readAsString(),
  );

  test(
    'verifyIdentityToken',
    () async {
      const token =
          'eyJraWQiOiJVYUlJRlkyZlc0IiwiYWxnIjoiUlMyNTYifQ.eyJpc3MiOiJodHRwczovL2FwcGxlaWQuYXBwbGUuY29tIiwiYXVkIjoiZGUubHVuYW9uZS5zaWduLWluLXdpdGgtYXBwbGUtZXhhbXBsZSIsImV4cCI6MTc1MjY2MjE1NywiaWF0IjoxNzUyNTc1NzU3LCJzdWIiOiIwMDA3MzkuOTBhYjcyZDVjNzg0NDRhOWJkZjFhM2ZiODBmZjY2NjAuMjEwNSIsImNfaGFzaCI6IlpDcnByb2lvRFNkU1FNb3FZVzMtN1EiLCJlbWFpbCI6InVnczZxdHBlaGZAcHJpdmF0ZXJlbGF5LmFwcGxlaWQuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImlzX3ByaXZhdGVfZW1haWwiOnRydWUsImF1dGhfdGltZSI6MTc1MjU3NTc1Nywibm9uY2Vfc3VwcG9ydGVkIjp0cnVlLCJyZWFsX3VzZXJfc3RhdHVzIjowfQ.YPLWr3FULJqVZ7o6rEtlXbI2Rh4USqmhyTRPcjzj3pQ1PmoWVYEe4kJKNgGCLPaMqB4ylaXo1gqvH5zdT_9llRhLzzSRJfXY7AIZifGe6ptZ6k44qYSo4ibACKBop39Uo3XTXACm2IN1gDAUW3MfC78ccE_E9z_U2i9gZ5Y32ce9TUrDX-t5cz9Lqaw8GbQAXKY4dbes_2ndHIza0NOOvWO3rB-B98OnirvivJow9Ei8m-w-dEEIEzq_zMNnVVJjMYKKS9Xk2QGOs71Wl1SFAc7QUos7jEqSHOaKIHHZY79ao73sAPU4kIZXGww1bU5c8W4Zg65TfHPkw7OEIgETcA';

      final identityToken = await withClock(
        Clock.fixed(DateTime.utc(2025, 7, 15, 10)),
        () => siwa.verifyIdentityToken(
          token,
          useBundleIdentifier: true,
          nonce: null,
        ),
      );

      expect(
        identityToken.userId,
        '000739.90ab72d5c78444a9bdf1a3fb80ff6660.2105',
      );

      expect(identityToken.email, 'ugs6qtpehf@privaterelay.appleid.com');
      expect(identityToken.emailVerified, isTrue);
      expect(identityToken.isPrivateEmail, isTrue);

      expect(identityToken.realUserStatus, 0);

      expect(identityToken.nonceSupported, isTrue);
      expect(identityToken.nonce, isNull);
    },
  );

  test(
    'decodeAppleServerNotification',
    () async {
      const payloadToken =
          'eyJraWQiOiJFNnE4M1JCMTVuIiwiYWxnIjoiUlMyNTYifQ.eyJpc3MiOiJodHRwczovL2FwcGxlaWQuYXBwbGUuY29tIiwiYXVkIjoiZGUubHVuYW9uZS5zaWduLWluLXdpdGgtYXBwbGUtZXhhbXBsZSIsImV4cCI6MTc1MjY1ODU5NywiaWF0IjoxNzUyNTcyMTk3LCJqdGkiOiI4c0lib0NlVUJRdVowTTd4OTFZS1pRIiwiZXZlbnRzIjoie1widHlwZVwiOlwiY29uc2VudC1yZXZva2VkXCIsXCJzdWJcIjpcIjAwMDczOS45MGFiNzJkNWM3ODQ0NGE5YmRmMWEzZmI4MGZmNjY2MC4yMTA1XCIsXCJldmVudF90aW1lXCI6MTc1MjU3MjE5MDcxOX0ifQ.AqPz9-w6L9K1QgVaeVdL8-3HPjmuxV5SRXgIJhzUNJU2e8Fr6QZ4zAwyXlOTwwE7bjiIOq31Hdc0ypNGlrrPHItJbQrwa4QjCYhDS88v_n5srgKxFFFCdd4M1m5zT1mnQLx6RFNzLFfG3sf0kYV0ndN37YRbmPFtPX3OmvBt5kZE_pLiXhuGqcEoFcLK7U9vbvxjGHaahWNwEouOZfO1bxXEeAWrX3Ua-10XtJCOBKQ3eQmxbkDyQG_sGVhJ7RVMVhQBdDSo8GZvh43g-y5HPCcttn5JzRrXhZJPOlMapTQEnaswa7b68RVJ_pgo39p2uUUitB_TzIycEL-B3Gx7kQ';

      final notification = await withClock(
        Clock.fixed(DateTime.utc(2025, 7, 15, 18)),
        () => siwa.decodeAppleServerNotification(payloadToken),
      );

      expect(
        notification,
        isA<AppleServerNotificationConsentRevoked>().having(
          (n) => n.userIdentifier,
          'userIdentifier',
          '000739.90ab72d5c78444a9bdf1a3fb80ff6660.2105',
        ),
      );
    },
  );
}
