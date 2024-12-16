import 'dart:async';

import 'package:fresh/fresh.dart';
import 'package:gql_exec/gql_exec.dart';
import 'package:gql_link/gql_link.dart';
import 'package:http/http.dart' as http;

/// Signature for `shouldRefresh` on [FreshLink].
typedef ShouldRefresh = bool Function(Response);

/// Signature for `refreshToken` on [FreshLink].
typedef RefreshToken<T> = Future<T> Function(T, http.Client);

/// {@template fresh_link}
/// A GraphQL Link which handles manages an authentication token automatically.
///
/// A constructor that returns a Fresh interceptor that uses the
/// [OAuth2Token] token, the standard token class and define the`
/// tokenHeader as 'authorization': '${token.tokenType} ${token.accessToken}'
///
/// ```dart
/// final freshLink = FreshLink(
///   tokenStorage: InMemoryTokenStorage(),
///   refreshToken: (token, client) {
///     // Perform refresh and return new token
///   },
/// );
/// final graphQLClient = GraphQLClient(
///   cache: InMemoryCache(),
///   link: Link.from([freshLink, HttpLink(uri: 'https://my.graphql.api')]),
/// );
/// ```
/// {@endtemplate}
class FreshLink<T> extends Link with FreshMixin<T> {
  /// {@macro fresh_link}
  FreshLink({
    required TokenStorage<T> tokenStorage,
    required RefreshToken<T?> refreshToken,
    required ShouldRefresh shouldRefresh,
    TokenHeaderBuilder<T?>? tokenHeader,
  })  : _refreshToken = refreshToken,
        _tokenHeader = (tokenHeader ?? (_) => <String, String>{}),
        _shouldRefresh = shouldRefresh {
    this.tokenStorage = tokenStorage;
  }

  ///{@template fresh_link}
  ///A GraphQL Link which handles manages an authentication token automatically.
  ///
  /// ```dart
  /// final freshLink = FreshLink.oAuth2(
  ///   tokenStorage: InMemoryTokenStorage<OAuth2Token>(),
  ///   refreshToken: (token, client) {
  ///     // Perform refresh and return new token
  ///   },
  /// );
  /// final graphQLClient = GraphQLClient(
  ///   cache: InMemoryCache(),
  ///   link: Link.from([freshLink, HttpLink(uri: 'https://my.graphql.api')]),
  /// );
  /// ```
  /// {@endtemplate}
  static FreshLink<T> oAuth2<T extends OAuth2Token>({
    required TokenStorage<T> tokenStorage,
    required RefreshToken<T?> refreshToken,
    required ShouldRefresh shouldRefresh,
    TokenHeaderBuilder<T?>? tokenHeader,
  }) {
    return FreshLink<T>(
      refreshToken: refreshToken,
      tokenStorage: tokenStorage,
      shouldRefresh: shouldRefresh,
      tokenHeader: tokenHeader ??
          (token) {
            return {
              'authorization': '${token?.tokenType} ${token?.accessToken}',
            };
          },
    );
  }

  final RefreshToken<T?> _refreshToken;
  final TokenHeaderBuilder<T?> _tokenHeader;
  final ShouldRefresh _shouldRefresh;

  Completer<T>? _refreshTokenCompleter;

  @override
  Stream<Response> request(Request request, [NextLink? forward]) async* {
    // Proactively ensure the token is fresh before sending the request
    await _ensureFreshToken();

    final currentToken = await token;
    final tokenHeaders = currentToken != null
        ? _tokenHeader(currentToken)
        : const <String, String>{};

    final updatedRequest = request.updateContextEntry<HttpLinkHeaders>(
      (headers) => HttpLinkHeaders(
        headers: {
          ...headers?.headers ?? <String, String>{},
          ...tokenHeaders,
        },
      ),
    );

    if (forward == null) return;

    await for (final result in forward(updatedRequest)) {
      final nextToken = await token;
      if (nextToken != null && _shouldRefresh(result)) {
        // Attempt to refresh token and retry if needed
        final refreshedToken = await _tryRefreshToken();
        if (refreshedToken == null) {
          // Refresh failed or token revoked, just yield the original result
          yield result;
        } else {
          // Retry the request with the refreshed token
          final refreshedHeaders = _tokenHeader(refreshedToken);
          final retriedRequest = request.updateContextEntry<HttpLinkHeaders>(
            (headers) => HttpLinkHeaders(
              headers: {
                ...headers?.headers ?? <String, String>{},
                ...refreshedHeaders,
              },
            ),
          );
          yield* forward(retriedRequest);
        }
      } else {
        // Token still valid or no refresh needed
        yield result;
      }
    }
  }

  /// Ensures that the current token is fresh (not expired).
  /// If expired, attempts a refresh. If another refresh is in progress, waits for it.
  Future<void> _ensureFreshToken() async {
    final currentToken = await token;
    if (currentToken == null) return; // No token, nothing to refresh.

    final isExpired = await isTokenExpired();
    if (!isExpired) return; // Token not expired, no need to refresh.

    await _refreshIfNeeded();
  }

  /// Attempts to refresh the token if needed and returns the refreshed token.
  /// If already refreshing, waits for the ongoing refresh.
  /// If refresh fails, throws or returns an error.
  Future<T?> _tryRefreshToken() async {
    try {
      return await _refreshIfNeeded();
    } catch (_) {
      // If an error occurs (like RevokeToken), return null to indicate failure.
      return null;
    }
  }

  /// Refresh the token if no refresh is in progress.
  /// If a refresh is in progress, waits for it.
  /// On success, returns the refreshed token.
  /// On failure, throws the corresponding error.
  Future<T> _refreshIfNeeded() async {
    // If a refresh is already in progress, await it.
    if (_refreshTokenCompleter != null) {
      return _refreshTokenCompleter!.future;
    }

    final completer = _refreshTokenCompleter = Completer<T>();
    final currentToken = await token;

    if (currentToken == null) {
      // No token to refresh
      completer.completeError(Exception('No token available for refresh'));
      _refreshTokenCompleter = null;
      return completer.future;
    }

    try {
      final refreshedToken = await _refreshToken(currentToken, http.Client());
      await setToken(refreshedToken);
      completer.complete(refreshedToken);
    } on RevokeTokenException {
      // Token cannot be refreshed, revoke it.
      await clearToken();
      completer.completeError(RevokeTokenException());
    } catch (error, stackTrace) {
      completer.completeError(error, stackTrace);
    } finally {
      _refreshTokenCompleter = null;
    }

    return completer.future;
  }
}
