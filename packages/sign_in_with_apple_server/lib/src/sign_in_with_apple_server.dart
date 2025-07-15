import 'dart:convert';

import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';
import 'package:http/http.dart' as http;
import 'package:meta/meta.dart';

class SignInWithApple {
  SignInWithApple({
    required SignInWithAppleConfiguration config,
    @visibleForTesting KeySource? keySource,
  })  : _config = config,
        _keySource = keySource;

  final SignInWithAppleConfiguration _config;

  final KeySource? _keySource;

  // https://developer.apple.com/documentation/signinwithapple/verifying-a-user#Verify-the-identity-token
  Future<IdentityToken> verifyIdentityToken(
    String identityToken, {
    /// Whether to verify the token against the bundle identifier or the service identifier
    ///
    /// For "native" logins on Apple platforms done through a deployed app, the bundle identifier must be used,
    /// while web and third-party platform sign-ins use the service ID.
    required bool useBundleIdentifier,

    /// The nonce to verify against.
    ///
    /// If `null` the token's nonce is ignored.
    required String? nonce,
  }) async {
    final key = await _getKey(_readKeyId(identityToken));

    // https://developer.apple.com/documentation/signinwithapple/authenticating-users-with-sign-in-with-apple#Retrieve-the-users-information-from-Apple-ID-servers
    final jwt = JWT.verify(
      identityToken,
      key,
      checkHeaderType: false,
      audience: useBundleIdentifier
          ? Audience.one(_config.bundleIdentifier)
          : Audience.one(_config.serviceIdentifier),
      issuer: 'https://appleid.apple.com',
    );

    // Example payload:
    // {
    //   "iss": "https://appleid.apple.com",
    //   "aud": "siwa-test",
    //   "exp": 1752596293,
    //   "iat": 1752509893,
    //   "sub": "000739.90ab72d5c78444a9bdf1a3fb80ff6660.2105",
    //   "nonce": "example-nonce",
    //   "c_hash": "DY96TlNKM1XAALITEacTog",
    //   "email": "ugs6qtpehf@privaterelay.appleid.com",
    //   "email_verified": true,
    //   "is_private_email": true,
    //   "auth_time": 1752509893,
    //   "nonce_supported": true,
    //   "real_user_status": 0
    // }
    final payload = jwt.payload as Map<String, dynamic>;
    final payloadNonce = payload['nonce'] as String?;

    if (nonce != null && nonce != payloadNonce) {
      throw Exception(
        'The identity token\'s nonce ("$payloadNonce") did not match the expected one ("$nonce")',
      );
    }

    return IdentityToken(
      userId: payload['sub'] as String,
      email: payload['email'] as String?,
      emailVerified: payload['email_verified'] as bool? ?? false,
      isPrivateEmail: payload['is_private_email'] as bool? ?? false,
      realUserStatus: payload['real_user_status'] as int?,
      nonce: payloadNonce,
      nonceSupported: payload['nonce_supported'] as bool? ?? false,
    );
  }

  /// Exchanges the initial authorization code for a refresh token.
  ///
  /// The response also includes an access token (which could be used for revocations),
  /// and a new identity token.
  // https://developer.apple.com/documentation/signinwithapplerestapi/generate-and-validate-tokens#Validate-the-authorization-grant-code
  Future<AuthorizationCodeExchangeResponse> exchangeAuthorizationCode(
    /// Per Apple's docs
    /// The authorization code received in an authorization response sent to your app.
    /// The code is single-use only and valid for five minutes. Authorization code validation requests require this parameter.
    String authorizationCode,
  ) async {
    final response = await http.post(
      Uri.https('appleid.apple.com', '/auth/token'),
      body: {
        'client_id': _config.bundleIdentifier,
        'client_secret': _createClientSecret(),
        'code': authorizationCode,
        'grant_type': 'authorization_code',
        'redirect_uri': _config.redirectUri,
      },
    );

    if (response.statusCode != 200) {
      throw Exception(
        'Could not exchange authorization code. Status code: ${response.statusCode}, message: ${response.body}',
      );
    }

    // Example response:
    // {
    //   "access_token": "adg61...67Or9",
    //   "token_type": "Bearer",
    //   "expires_in": 3600,
    //   "refresh_token": "rca7...lABoQ",
    //   "id_token": "eyJra...96sZg"
    // }
    final payload = jsonDecode(response.body) as Map;

    return AuthorizationCodeExchangeResponse(
      accessToken: payload['access_token'] as String,
      accessTokenExpiresIn: payload['expires_in'] as int,
      idToken: payload['id_token'] as String,
      refreshToken: payload['refresh_token'] as String,
    );
  }

  /// Uses the refresh token to get the latest state of the authorization.
  ///
  /// If it is in good standing, this will return the identity token and an access token.
  Future<RefreshTokenValidationResponse> validateRefreshToken(
    String refreshToken,
  ) async {
    final response = await http.post(
      Uri.https('appleid.apple.com', '/auth/token'),
      body: {
        'client_id': _config.bundleIdentifier,
        'client_secret': _createClientSecret(),
        'grant_type': 'refresh_token',
        'refresh_token': refreshToken,
      },
    );

    // Example response:
    // {
    //   "access_token": "adg61...67Or9",
    //   "token_type": "Bearer",
    //   "expires_in": 3600,
    //   "id_token": "eyJra...96sZg"
    // }
    final payload = jsonDecode(response.body) as Map;

    return RefreshTokenValidationResponse(
      accessToken: payload['access_token'] as String,
      accessTokenExpiresIn: payload['expires_in'] as int,
      idToken: payload['id_token'] as String,
    );
  }

  /// Revokes the authorization for the user.
  Future<void> revokeAuthorization({
    required String refreshToken,
  }) async {
    final response = await http.post(
      Uri.https('appleid.apple.com', '/auth/revoke'),
      body: {
        'client_id': _config.bundleIdentifier,
        'client_secret': _createClientSecret(),
        'token': refreshToken,
        'token_type_hint': 'refresh_token',
      },
    );

    if (response.statusCode != 200) {
      throw Exception('Failed to revoke authorization. ${response.body}');
    }
  }

  String _readKeyId(String jwtToken) {
    final jwt = JWT.decode(jwtToken);

    return jwt.header!['kid'] as String;
  }

  Future<JWTKey> _getKey(String keyId) async {
    final keyJson = _keySource != null
        ? await _keySource()
        : (await http.get(
            Uri.parse('https://appleid.apple.com/auth/keys'),
          ))
            .body;

    final keys = ((jsonDecode(keyJson) as Map)['keys'] as List)
        .cast<Map<String, dynamic>>();

    for (final keyMap in keys) {
      if (keyMap['kid'] == keyId) {
        return JWTKey.fromJWK(keyMap);
      }
    }

    throw Exception('Did not find key "$keyId"');
  }

  String _createClientSecret() {
    return JWT(
      {
        'exp': (DateTime.now()
                    .add(const Duration(minutes: 10))
                    .millisecondsSinceEpoch /
                1000)
            .floor(),
      },
      subject: _config.bundleIdentifier,
      audience: Audience.one('https://appleid.apple.com'),
      issuer: _config.teamId,
      header: {
        'kid': _config.keyId,
      },
    ).sign(
      _config.key,
      algorithm: JWTAlgorithm.ES256,
    );
  }

  Future<AppleServerNotification> decodeAppleServerNotification(
    /// The received payload token (not the entire body).
    String payloadToken,
  ) async {
    final key = await _getKey(_readKeyId(payloadToken));

    // https://developer.apple.com/documentation/signinwithapple/authenticating-users-with-sign-in-with-apple#Retrieve-the-users-information-from-Apple-ID-servers
    final jwt = JWT.verify(
      payloadToken,
      key,
      checkHeaderType: false,
      audience: Audience.one(_config.bundleIdentifier),
      issuer: 'https://appleid.apple.com',
    );

    // For example payloads see https://developer.apple.com/documentation/signinwithapple/processing-changes-for-sign-in-with-apple-accounts
    final payload = jwt.payload as Map<String, dynamic>;

    final events =
        jsonDecode(payload['events'] as String) as Map<String, dynamic>;

    final type = events['type'] as String;
    final userIdentifier = events['sub'] as String;

    switch (type) {
      case 'email-disabled':
        return AppleServerNotificationEmailDisabled(
          userIdentifier: userIdentifier,
          email: events['email'] as String,
        );

      case 'email-enabled':
        return AppleServerNotificationEmailEnabled(
          userIdentifier: userIdentifier,
          email: events['email'] as String,
        );

      case 'consent-revoked':
        return AppleServerNotificationConsentRevoked(
          userIdentifier: userIdentifier,
        );

      case 'account-delete':
        return AppleServerNotificationAccountDelete(
          userIdentifier: userIdentifier,
        );

      default:
        throw Exception('Unexpected notification type: "$type".');
    }
  }
}

/// Email details and real user status are only passed on the initial login.
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

class SignInWithAppleConfiguration {
  SignInWithAppleConfiguration({
    required this.serviceIdentifier,
    required this.bundleIdentifier,
    required this.redirectUri,
    required this.teamId,
    required this.keyId,
    required this.key,
  });

  final String bundleIdentifier;

  final String serviceIdentifier;

  final String redirectUri;

  final String teamId;

  /// ID of the service key
  final String keyId;

  final ECPrivateKey key;
}

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

  final String refreshToken;

  @override
  String toString() {
    return 'AuthorizationCodeExchangeResponse(accessToken: $accessToken, accessTokenExpiresIn: $accessTokenExpiresIn, idToken: $idToken, refreshToken: $refreshToken)';
  }
}

class RefreshTokenValidationResponse {
  RefreshTokenValidationResponse({
    required this.accessToken,
    required this.accessTokenExpiresIn,
    required this.idToken,
  });

  final String accessToken;

  final int accessTokenExpiresIn;

  final String idToken;

  @override
  String toString() {
    return 'RefreshTokenValidationResponse(accessToken: $accessToken, accessTokenExpiresIn: $accessTokenExpiresIn, idToken: $idToken)';
  }
}

sealed class AppleServerNotification {}

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

typedef KeySource = Future<String> Function();
