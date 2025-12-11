import 'dart:convert';
import 'dart:io';

import 'package:relic/io_adapter.dart';
import 'package:relic/relic.dart';
import 'package:sign_in_with_apple_server/sign_in_with_apple_server.dart';
import 'package:sign_in_with_apple_server_relic/sign_in_with_apple_server_relic.dart';
import 'package:uuid/uuid.dart';

late final SignInWithApple siwa;

late final String androidAppPackage;

final activityLogEntries = <ActivityLogEntry>[];

final activeUserSessions = <String, List<UserSession>>{};

typedef UserSession = ({
  UuidValue id,
  DateTime createdAt,
  String refreshToken,
  bool useBundleIdentifier,
});

Future<void> run() async {
  siwa = SignInWithApple(
    config: SignInWithAppleConfiguration(
      serviceIdentifier: Platform.environment['SERVICE_ID']!,
      bundleIdentifier: Platform.environment['BUNDLE_IDENTIFIER']!,
      redirectUri: Platform.environment['REDIRECT_URI']!,
      teamId: Platform.environment['TEAM_ID']!,
      keyId: Platform.environment['KEY_ID']!,
      key: File(Platform.environment['KEY_FILE_PATH']!).readAsStringSync(),
    ),
  );
  // You might need to configure similar links for other platforms, or use a more flexible set up with targets.
  androidAppPackage = Platform.environment['ANDROID_APP_PACKAGE']!;

  final router = Router<Handler>()
    // These 3 are endpoints that apps commonly implement
    ..post(
      '/api/sign-in',
      signInHandler(siwa, signIn),
    )
    ..post(
      '/hooks/apple-return-url',
      redirectUrlHandler(redirectUrl),
    )
    ..post(
      '/hooks/apple-server-to-server',
      serverToServerNotificationHandler(siwa, serverToServerNotification),
    )

    // Optional endpoint (to showcase using Apple's API with the refresh token on demand)
    ..post('/api/revoke', revoke)

    // Group of admin handlers, which a normal server would not expose
    ..get('/api/admin/activity-log', activityLog)
    ..get('/api/admin/sessions', sessions)
    ..post('/api/admin/refresh-token', refreshToken)
    ..post('/api/admin/revoke', revokeAuthorization)
    ..get('/css', css)
    ..get('/', landingPage)
    // Health check path for render.com
    ..get('/healthz', healthCheck);

  final handler = const Pipeline()
      .addMiddleware(logRequests())
      .addMiddleware(routeWith(router))
      .addHandler(fallback404);

  // Start the server with the handler
  final port = int.parse(Platform.environment['PORT'] ?? '8080');
  await serve(handler, InternetAddress.anyIPv4, port);

  print('Serving at http://localhost:$port');
}

ResponseContext fallback404(RequestContext ctx) {
  return (ctx as RespondableContext).withResponse(Response.notFound());
}

// https://developer.apple.com/documentation/signinwithapple/processing-changes-for-sign-in-with-apple-accounts
Future<void> serverToServerNotification(
  RequestContext ctx,
  AppleServerNotification notification,
) async {
  activityLogEntries.add(
    ActivityLogEntry(
      endpoint: '${ctx.request.method.value} ${ctx.request.requestedUri.path}',
      data: {
        'body': switch (notification) {
          AppleServerNotificationEmailDisabled() =>
            'AppleServerNotificationEmailDisabled(userIdentifier: ${notification.userIdentifier}, email: ${notification.email})',
          AppleServerNotificationEmailEnabled() =>
            'AppleServerNotificationEmailEnabled(userIdentifier: ${notification.userIdentifier}, email: ${notification.email})',
          AppleServerNotificationConsentRevoked() =>
            'AppleServerNotificationConsentRevoked(userIdentifier: ${notification.userIdentifier})',
          AppleServerNotificationAccountDelete() =>
            'AppleServerNotificationAccountDelete(userIdentifier: ${notification.userIdentifier})',
        },
        'query': ctx.request.requestedUri.query,
      },
    ),
  );

  final deletedUserIdentifer = switch (notification) {
    AppleServerNotificationEmailDisabled() => null,
    AppleServerNotificationEmailEnabled() => null,
    AppleServerNotificationConsentRevoked() => notification.userIdentifier,
    AppleServerNotificationAccountDelete() => notification.userIdentifier,
  };

  if (deletedUserIdentifer != null) {
    activeUserSessions.remove(deletedUserIdentifer);
  }
}

Future<Uri> redirectUrl(RequestContext ctx, String body) async {
  activityLogEntries.add(
    ActivityLogEntry(
      endpoint: '${ctx.request.method.value} ${ctx.request.requestedUri.path}',
      data: {
        'query': ctx.request.requestedUri.query,
        'body': body,
      },
    ),
  );

  final formData = Uri(query: body).queryParameters;

  final authorizationCode = formData['code']!;
  final identityToken = formData['id_token']!;

  final userAgent = ctx.request.headers.userAgent;
  // Alternatively use the `state` to detect target action (so this would not be triggered in browsers on Android)
  if (userAgent != null &&
      (userAgent.contains('Android') || userAgent.contains('Linux'))) {
    // Important to always forward, even on error (contained in the `body` parameters), so the in-app browser closes in the app
    final appDeeplink = Uri(
      scheme: 'intent',
      host: 'callback',
      query: body,
      fragment: 'Intent;package=$androidAppPackage;scheme=signinwithapple;end',
    );

    print(appDeeplink);

    return appDeeplink;
  }

  /// Check that the incoming link is valid
  final verifiedIdentityToken = await siwa.verifyIdentityToken(
    identityToken,
    useBundleIdentifier: false,
    nonce: null,
  );

  print('verifiedIdentityToken: $verifiedIdentityToken');

  final refreshToken = await siwa.exchangeAuthorizationCode(
    authorizationCode,
    useBundleIdentifier: false,
  );

  print('refreshToken: $refreshToken');

  final session = (
    id: const Uuid().v7obj(),
    createdAt: DateTime.now(),
    refreshToken: refreshToken.refreshToken,
    useBundleIdentifier: false,
  );

  activeUserSessions.update(
    verifiedIdentityToken.userId,
    (value) => value..add(session),
    ifAbsent: () => [session],
  );

  // Non-pop-up web sign-ins just go back to the homepage
  return Uri.https('sign-in-with-apple.lunaone.de');
}

Future<void> signIn(
  RequestContext ctx,
  IdentityToken identityToken,
  String refreshToken, {
  required bool useBundleIdentifier,

  /// Set to whatever the user specified (if requested in the scopes).
  String? firstName,

  /// Set to whatever the user specified (if requested in the scopes).
  String? lastName,
}) async {
  final authorizationCode =
      ctx.request.requestedUri.queryParameters['authorizationCode'];

  final identityTokenParameter =
      ctx.request.requestedUri.queryParameters['identityToken'];

  final firstName = ctx.request.requestedUri.queryParameters['firstName'];
  final lastName = ctx.request.requestedUri.queryParameters['lastName'];
  final useBundleIdentifier =
      ctx.request.requestedUri.queryParameters['useBundleIdentifier'] == 'true';

  activityLogEntries.add(
    ActivityLogEntry(
      endpoint: '${ctx.request.method.value} ${ctx.request.requestedUri.path}',
      data: {
        'authorizationCode': authorizationCode,
        'identityToken': identityTokenParameter,
        'firstName': firstName,
        'lastName': lastName,
        'useBundleIdentifier': useBundleIdentifier.toString(),
      },
    ),
  );

  final session = (
    id: const Uuid().v7obj(),
    createdAt: DateTime.now(),
    refreshToken: refreshToken,
    useBundleIdentifier: useBundleIdentifier,
  );

  activeUserSessions.update(
    identityToken.userId,
    (value) => value..add(session),
    ifAbsent: () => [session],
  );
}

ResponseContext revoke(RequestContext ctx) {
  return (ctx as RespondableContext).withResponse(Response.ok());
}

ResponseContext activityLog(RequestContext ctx) {
  return (ctx as RespondableContext).withResponse(
    Response.ok(
      body: Body.fromString(
        [
          for (final entry in activityLogEntries.reversed) ...[
            '-> ${entry.endpoint}',
            '',
            '     at ${entry.at.toIso8601String()}',
            '',
            for (final parameter in entry.data.entries)
              '     ${parameter.key} = ${parameter.value}',
            '',
            '',
          ],
        ].join('\n'),
      ),
    ),
  );
}

ResponseContext sessions(RequestContext ctx) {
  return (ctx as RespondableContext).withResponse(
    Response.ok(
      body: Body.fromString(
        jsonEncode({
          'sessionsByUserId': {
            for (final MapEntry(key: userId, value: sessions)
                in activeUserSessions.entries)
              userId: [
                for (final session in sessions)
                  <String, dynamic>{
                    'id': session.id.uuid,
                    'createdAt': session.createdAt.toIso8601String(),
                    'refreshToken': session.refreshToken,
                    'useBundleIdentifier': session.useBundleIdentifier,
                  },
              ],
          },
        }),
        mimeType: MimeType.json,
      ),
    ),
  );
}

Future<ResponseContext> refreshToken(RequestContext ctx) async {
  try {
    final body = await utf8.decodeStream(ctx.request.body.read());

    activityLogEntries.add(
      ActivityLogEntry(
        endpoint:
            '${ctx.request.method.value} ${ctx.request.requestedUri.path}',
        data: {
          'query': ctx.request.requestedUri.query,
          'body': body,
        },
      ),
    );

    final sessionId = UuidValue.fromString(
      ctx.request.requestedUri.queryParameters['sessionId']!,
    )..validate();

    final (userId, session) = activeUserSessions.entries
        .expand((x) => x.value.map((k) => (x.key, k)))
        .firstWhere((x) => x.$2.id == sessionId);

    print(userId);
    print(activeUserSessions);

    final refreshToken = await siwa.validateRefreshToken(
      session.refreshToken,
      useBundleIdentifier: session.useBundleIdentifier,
    );

    final verifiedIdentityToken = await siwa.verifyIdentityToken(
      refreshToken.idToken,
      useBundleIdentifier: false,
      nonce: null,
    );

    return (ctx as RespondableContext).withResponse(
      Response.ok(
        body: Body.fromString(
          'Refreshed token\n'
          '$verifiedIdentityToken',
        ),
      ),
    );
  } catch (e, stackTrace) {
    print(e);
    print(stackTrace);

    rethrow;
  }
}

Future<ResponseContext> revokeAuthorization(RequestContext ctx) async {
  try {
    final body = await utf8.decodeStream(ctx.request.body.read());

    activityLogEntries.add(
      ActivityLogEntry(
        endpoint:
            '${ctx.request.method.value} ${ctx.request.requestedUri.path}',
        data: {
          'query': ctx.request.requestedUri.query,
          'body': body,
        },
      ),
    );

    final sessionId = UuidValue.fromString(
      ctx.request.requestedUri.queryParameters['sessionId']!,
    )..validate();

    print(sessionId);
    print(activeUserSessions);

    final (userId, session) = activeUserSessions.entries
        .expand((x) => x.value.map((k) => (x.key, k)))
        .firstWhere((x) => x.$2.id == sessionId);

    await siwa.revokeAuthorization(
      refreshToken: session.refreshToken,
      useBundleIdentifier: session.useBundleIdentifier,
    );

    activeUserSessions.update(userId, (x) => x..remove(session));

    return (ctx as RespondableContext).withResponse(
      Response.ok(),
    );
  } catch (e, stackTrace) {
    print(e);
    print(stackTrace);

    rethrow;
  }
}

ResponseContext healthCheck(RequestContext ctx) {
  return (ctx as RespondableContext).withResponse(Response.ok());
}

ResponseContext css(RequestContext ctx) {
  return (ctx as RespondableContext).withResponse(
    Response.ok(
      body: Body.fromString(
        File('./assets/pico.min.css').readAsStringSync(),
        mimeType: MimeType.css,
      ),
    ),
  );
}

ResponseContext landingPage(RequestContext ctx) {
  return (ctx as RespondableContext).withResponse(
    Response.ok(
      body: Body.fromString(
        File('./assets/index.html')
            .readAsStringSync()
            .replaceFirst('[CLIENT_ID]', Platform.environment['SERVICE_ID']!)
            .replaceFirst(
              '[REDIRECT_URI]',
              Platform.environment['REDIRECT_URI']!,
            ),
        mimeType: MimeType.html,
      ),
    ),
  );
}

class ActivityLogEntry {
  ActivityLogEntry({
    required this.endpoint,
    required this.data,
    DateTime? at,
  }) : at = at ?? DateTime.now();

  final DateTime at;

  final String endpoint;

  final Map<String, String?> data;
}
