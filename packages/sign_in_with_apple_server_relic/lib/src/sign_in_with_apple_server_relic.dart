import 'dart:async';
import 'dart:convert';

import 'package:relic/relic.dart';
import 'package:sign_in_with_apple_server/sign_in_with_apple_server.dart';

/// Handler to server-to-server notifications coming from Apple.
///
/// To be mounted as a `POST` handler under the URL configured in Apple's developer portal.
Handler serverToServerNotificationHandler(
  SignInWithApple signInWithApple,
  FutureOr<void> Function(
    RequestContext ctx,
    AppleServerNotification notification,
  ) handler,
) {
  return (RequestContext ctx) async {
    final body = await utf8.decodeStream(ctx.request.body.read());

    final payload = (jsonDecode(body) as Map)['payload'] as String;

    final notification = await signInWithApple.decodeAppleServerNotification(
      payload,
    );

    await handler(ctx, notification);

    return ctx.withResponse(Response.ok());
  };
}

/// Handler for the incoming re-direct from non-popup web-based logins,
/// e.g. from an Android in-app browser.
///
/// For mobile apps this usually ends in a redirect back to the app via
/// a deep link, whereas stand-alone browser flows without pop-up would redirect
/// back to the web app.
Handler redirectUrlHandler(
  /// Handler returning the target redirect URL.
  ///
  /// For deep-links back to the app using the Flutter `sign_in_with_apple` package the `body` needs
  /// to be forwarded as the raw `query` parameter.
  ///
  /// Alternative flows are possible as well: For example if the server
  /// already knows which user to associate the sign-in with, they could do that
  /// here and provide a new session for the client in the return URL.
  ///
  /// The benefit of currently implemented flow is that the client-side handling works the same
  /// way for both Apple-platform and web-based logins (at the cost of the client
  /// posting the very same data again to the server).
  FutureOr<Uri> Function(RequestContext ctx, String body) handler,
) {
  return (RequestContext ctx) async {
    final body = await utf8.decodeStream(ctx.request.body.read());

    final target = await handler(ctx, body);

    return ctx.withResponse(Response.found(target));
  };
}

Handler signInHandler(
  SignInWithApple signInWithApple,
  FutureOr<void> Function(
    RequestContext ctx,
    IdentityToken identityToken,

    /// Refresh token, which needs to be stored with the `useBundleIdentifier` parameter
    String refreshToken, {
    required bool useBundleIdentifier,

    /// Set to whatever the user specified (if requested in the scopes).
    String? firstName,

    /// Set to whatever the user specified (if requested in the scopes).
    String? lastName,
  }) handler,
) {
  return (RequestContext ctx) async {
    final authorizationCode =
        ctx.request.requestedUri.queryParameters['authorizationCode'];

    if (authorizationCode == null) {
      return ctx.withMissingQueryParameterResponse('authorizationCode');
    }

    final identityToken =
        ctx.request.requestedUri.queryParameters['identityToken'];

    if (identityToken == null) {
      return ctx.withMissingQueryParameterResponse('identityToken');
    }

    final firstName = ctx.request.requestedUri.queryParameters['firstName'];
    final lastName = ctx.request.requestedUri.queryParameters['lastName'];
    final useBundleIdentifier =
        ctx.request.requestedUri.queryParameters['useBundleIdentifier'] ==
            'true';

    final verifiedIdentityToken = await signInWithApple.verifyIdentityToken(
      identityToken,
      useBundleIdentifier: useBundleIdentifier,
      nonce: null,
    );

    final authorizationCodeExchangeResponse =
        await signInWithApple.exchangeAuthorizationCode(
      authorizationCode,
      useBundleIdentifier: useBundleIdentifier,
    );

    await handler(
      ctx,
      verifiedIdentityToken,
      authorizationCodeExchangeResponse.refreshToken,
      useBundleIdentifier: useBundleIdentifier,
      firstName: firstName,
      lastName: lastName,
    );

    return ctx.withResponse(Response.ok());
  };
}

extension on RequestContext {
  ResponseContext withMissingQueryParameterResponse(String parameterName) {
    return (this as RespondableContext).withResponse(
      Response.badRequest(
        body: Body.fromString('Missing query parameter "$parameterName".'),
      ),
    );
  }

  ResponseContext withResponse(Response r) {
    return (this as RespondableContext).withResponse(r);
  }
}
