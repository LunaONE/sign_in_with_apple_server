import 'dart:convert';
import 'dart:io';

import 'package:relic/io_adapter.dart';
import 'package:relic/relic.dart';
import 'package:sign_in_with_apple_server/sign_in_with_apple_server.dart';

late final SignInWithApple siwa;

late final String androidAppPackage;

final activityLogEntries = <ActivityLogEntry>[];

final refreshTokensByUserIdentifier =
    <String, ({String refreshToken, bool useBundleIdentifier})>{};

Future<void> main() async {
  siwa = SignInWithApple(
    config: SignInWithAppleConfiguration(
      serviceIdentifier: Platform.environment['SERVICE_ID']!,
      bundleIdentifier: Platform.environment['BUNDLE_IDENTIFIER']!,
      redirectUri: Platform.environment['REDIRECT_URI']!,
      teamId: Platform.environment['TEAM_ID']!,
      keyId: Platform.environment['KEY_ID']!,
      key: ECPrivateKey(
        File(Platform.environment['KEY_FILE_PATH']!).readAsStringSync(),
      ),
    ),
  );
  // You might need to configure similar links for other platforms, or use a more flexible set up with targets.
  androidAppPackage = Platform.environment['ANDROID_APP_PACKAGE']!;

  // Setup router
  final router = Router<Handler>()
    ..post('/hooks/apple-server-to-server', serverHook)
    ..post('/hooks/apple-return-url', redirectUrl)
    // Example user-facing endpoints
    ..post('/api/sign-in', signIn)
    ..post('/api/revoke', revoke)
    // SiwA web-page login
    ..get('/web-signin', siwaWeb)
    // Group of admin handlers, which a normal server would not expose
    ..get('/admin/activity-log', activityLog)
    ..get('/admin/sessions', sessions)
    ..post('/admin/refresh-token', refreshToken)
    ..post('/admin/revoke', revokeAuthorization)
    // Health check path for render.com
    ..get('/healthz', healthCheck);

  final handler = const Pipeline()
      .addMiddleware(logRequests())
      .addMiddleware(routeWith(router))
      .addHandler(landingPage);

  // Start the server with the handler
  final port = int.parse(Platform.environment['PORT'] ?? '8080');
  await serve(handler, InternetAddress.anyIPv4, port);

  print('Serving at http://localhost:$port');
}

// https://developer.apple.com/documentation/signinwithapple/processing-changes-for-sign-in-with-apple-accounts
Future<ResponseContext> serverHook(final RequestContext ctx) async {
  final body = await utf8.decodeStream(ctx.request.body.read());

  print('body: $body');

  activityLogEntries.add(
    ActivityLogEntry(
      endpoint: '${ctx.request.method.value} ${ctx.request.requestedUri.path}',
      data: {
        'body': body,
        'query': ctx.request.requestedUri.query,
      },
    ),
  );

  final payload = (jsonDecode(body) as Map)['payload'] as String;

  print(await siwa.decodeAppleServerNotification(payload));

  return (ctx as RespondableContext).withResponse(Response.ok());
}

Future<ResponseContext> redirectUrl(final RequestContext ctx) async {
  final body = await utf8.decodeStream(ctx.request.body.read());

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
  if (userAgent != null && userAgent.contains('Android')) {
    // Important to always forward, even on error (contained in the `body` parameters), so the in-app browser closes in the app
    final appDeeplink = Uri(
      scheme: 'intent',
      host: 'callback',
      query: body,
      fragment: 'Intent;package=$androidAppPackage;scheme=signinwithapple;end',
    );

    print(appDeeplink);

    return (ctx as RespondableContext).withResponse(
      Response.found(appDeeplink),
    );
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

  refreshTokensByUserIdentifier[verifiedIdentityToken.userId] = (
    refreshToken: refreshToken.refreshToken,
    useBundleIdentifier: false,
  );

  return (ctx as RespondableContext).withResponse(
    Response.ok(
      body: Body.fromString('$verifiedIdentityToken'),
    ),
  );
}

Future<ResponseContext> signIn(final RequestContext ctx) async {
  final authorizationCode =
      ctx.request.requestedUri.queryParameters['authorizationCode'];

  if (authorizationCode == null) {
    return ctx.withMissingQueryParameterResponse("authorizationCode");
  }

  final identityToken =
      ctx.request.requestedUri.queryParameters['identityToken'];

  if (identityToken == null) {
    return ctx.withMissingQueryParameterResponse("identityToken");
  }

  final firstName = ctx.request.requestedUri.queryParameters['firstName'];
  final lastName = ctx.request.requestedUri.queryParameters['lastName'];
  final useBundleIdentifier =
      ctx.request.requestedUri.queryParameters['useBundleIdentifier'] == 'true';

  activityLogEntries.add(
    ActivityLogEntry(
      endpoint: '${ctx.request.method.value} ${ctx.request.requestedUri.path}',
      data: {
        'authorizationCode': authorizationCode,
        'identityToken': identityToken,
        'firstName': firstName,
        'lastName': lastName,
        'useBundleIdentifier': useBundleIdentifier.toString(),
      },
    ),
  );

  try {
    final verifiedIdentityToken = await siwa.verifyIdentityToken(
      identityToken,
      useBundleIdentifier: useBundleIdentifier,
      nonce: null,
    );

    print('verifiedIdentityToken: $verifiedIdentityToken');

    final refreshToken = await siwa.exchangeAuthorizationCode(
      authorizationCode,
      useBundleIdentifier: useBundleIdentifier,
    );

    print('refreshToken: $refreshToken');

    refreshTokensByUserIdentifier[verifiedIdentityToken.userId] = (
      refreshToken: refreshToken.refreshToken,
      useBundleIdentifier: useBundleIdentifier,
    );

    return (ctx as RespondableContext).withResponse(
      Response.ok(
        body: Body.fromString('$verifiedIdentityToken'),
      ),
    );
  } catch (e, s) {
    print(e);
    print(s);

    rethrow;
  }
}

ResponseContext revoke(final RequestContext ctx) {
  return (ctx as RespondableContext).withResponse(Response.ok());
}

ResponseContext activityLog(final RequestContext ctx) {
  return (ctx as RespondableContext).withResponse(Response.ok(
      body: Body.fromString([
    for (final entry in activityLogEntries.reversed) ...[
      '-> ${entry.endpoint}',
      '',
      '     at ${entry.at.toIso8601String()}',
      '',
      for (final parameter in entry.data.entries)
        '     ${parameter.key} = ${parameter.value}',
      '',
      '',
    ]
  ].join('\n'))));
}

ResponseContext sessions(final RequestContext ctx) {
  return (ctx as RespondableContext).withResponse(
    Response.ok(
      body: Body.fromString(
        [
          '<h1>Active Sessions</h1>',
          '<ul>',
          for (final entry in refreshTokensByUserIdentifier.entries) ...[
            '<li>'
                '${entry.key}'
                '<form action="/admin/refresh-token" method="post">'
                '  <input type="hidden" name="userId" value="${entry.key}">'
                '  <input type="submit" value="Refresh token" />'
                '</form>'
                '<form action="/admin/revoke" method="post">'
                '  <input type="hidden" name="userId" value="${entry.key}">'
                '  <input type="submit" value="Revoke authorization" />'
                '</form>'
                '</li>'
          ],
          '</ul>'
        ].join('\n'),
        mimeType: MimeType.html,
      ),
    ),
  );
}

Future<ResponseContext> refreshToken(final RequestContext ctx) async {
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

    final formData = Uri(query: body).queryParameters;
    final userId = formData['userId']!;

    print(userId);
    print(refreshTokensByUserIdentifier);

    final refreshToken = await siwa.validateRefreshToken(
      refreshTokensByUserIdentifier[userId]!.refreshToken,
      useBundleIdentifier:
          refreshTokensByUserIdentifier[userId]!.useBundleIdentifier,
    );

    final verifiedIdentityToken = await siwa.verifyIdentityToken(
      refreshToken.idToken,
      useBundleIdentifier: false,
      nonce: null,
    );

    return (ctx as RespondableContext).withResponse(Response.ok(
        body: Body.fromString(
      'Refreshed token\n'
      ''
      '$verifiedIdentityToken',
    )));
  } catch (e, stackTrace) {
    print(e);
    print(stackTrace);

    rethrow;
  }
}

Future<ResponseContext> revokeAuthorization(final RequestContext ctx) async {
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

    final formData = Uri(query: body).queryParameters;
    final userId = formData['userId']!;

    print(userId);
    print(refreshTokensByUserIdentifier);

    await siwa.revokeAuthorization(
      refreshToken: refreshTokensByUserIdentifier[userId]!.refreshToken,
      useBundleIdentifier:
          refreshTokensByUserIdentifier[userId]!.useBundleIdentifier,
    );

    refreshTokensByUserIdentifier.remove(userId);

    return (ctx as RespondableContext).withResponse(
      Response.found(Uri.parse('/admin/sessions')),
    );
  } catch (e, stackTrace) {
    print(e);
    print(stackTrace);

    rethrow;
  }
}

ResponseContext healthCheck(final RequestContext ctx) {
  return (ctx as RespondableContext).withResponse(Response.ok());
}

ResponseContext landingPage(final RequestContext ctx) {
  return (ctx as RespondableContext).withResponse(
    Response.ok(
      body: Body.fromString(
        File('./assets/index.html').readAsStringSync(),
        mimeType: MimeType.html,
      ),
    ),
  );
}

ResponseContext siwaWeb(final RequestContext ctx) {
  return (ctx as RespondableContext).withResponse(
    Response.ok(
      body: Body.fromString(
        File('./assets/siwa_web.html')
            .readAsStringSync()
            .replaceFirst('[CLIENT_ID]', Platform.environment['SERVICE_ID']!)
            .replaceFirst(
                '[REDIRECT_URI]', Platform.environment['REDIRECT_URI']!),
        mimeType: MimeType.html,
      ),
    ),
  );
}

class ActivityLogEntry {
  ActivityLogEntry({
    DateTime? at,
    required this.endpoint,
    required this.data,
  }) : at = at ?? DateTime.now();

  final DateTime at;

  final String endpoint;

  final Map<String, String?> data;
}

extension on RequestContext {
  ResponseContext withMissingQueryParameterResponse(String parameterName) {
    return (this as RespondableContext).withResponse(
      Response.badRequest(
        body: Body.fromString('Missing query parameter "$parameterName".'),
      ),
    );
  }
}
