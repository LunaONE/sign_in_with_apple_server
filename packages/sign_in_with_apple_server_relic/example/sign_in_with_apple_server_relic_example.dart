import 'dart:convert';
import 'dart:io';

import 'package:relic/io_adapter.dart';
import 'package:relic/relic.dart';
import 'package:sign_in_with_apple_server/sign_in_with_apple_server.dart';

late final SignInWithApple siwa;

final activityLogEntries = <ActivityLogEntry>[];

final refreshTokensByUserIdentifier = <String, String>{};

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

  // Setup router
  final router = Router<Handler>()
    ..post('/hooks/apple-server-to-server', serverHook)
    ..get('/hooks/apple-return-url', redirectUrl)
    // Example user-facing endpoints
    ..post('/api/sign-in', signIn)
    ..post('/api/revoke', revoke)
    // Debug activity log
    ..get('/activity-log', activityLog)
    // Health check path for render.com
    ..get('/healthz', healthCheck);

  final handler = const Pipeline()
      .addMiddleware(logRequests())
      .addMiddleware(routeWith(router))
      .addHandler(
        respondWith(
          (final _) => Response.ok(
            body: Body.fromString(
              'Test server for <a href="https://pub.dev/packages/sign_in_with_apple_server">sign_in_with_apple_server</a>.'
              '<br /><br />'
              'View the debug activity log <a href="/activity-log">here</a>.'
              '<br /><br />'
              'By <a href="https://www.lunaone.de/flutter">LunaONE GmbH</a>.',
              mimeType: MimeType.html,
            ),
          ),
        ),
      );

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

ResponseContext redirectUrl(final RequestContext ctx) {
  print(ctx.request.body);

  return (ctx as RespondableContext).withResponse(Response.ok());
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
    );

    print('refreshToken: $refreshToken');

    refreshTokensByUserIdentifier[verifiedIdentityToken.userId] =
        refreshToken.refreshToken;

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

ResponseContext healthCheck(final RequestContext ctx) {
  return (ctx as RespondableContext).withResponse(Response.ok());
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
