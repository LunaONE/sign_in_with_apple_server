FROM dart:3.6.1 AS build

WORKDIR /app
COPY . .
WORKDIR /app/packages/sign_in_with_apple_server_relic/example

RUN dart pub get
RUN dart compile exe example.dart -o server

# Build minimal serving image from AOT-compiled `/server` and required system
# libraries and configuration files stored in `/runtime/` from the build stage.
FROM scratch
COPY --from=build /runtime/ /
COPY --from=build /app/packages/sign_in_with_apple_server_relic/example/server /app/bin/
COPY --from=build /app/packages/sign_in_with_apple_server_relic/example/assets /app/bin/assets/

# Start server.
EXPOSE 10000
WORKDIR /app/bin/
CMD ["/app/bin/server"]