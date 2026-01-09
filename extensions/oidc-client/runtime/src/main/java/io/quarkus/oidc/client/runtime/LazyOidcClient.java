package io.quarkus.oidc.client.runtime;

import java.io.IOException;
import java.util.Map;
import java.util.function.Function;

import io.quarkus.oidc.client.OidcClient;
import io.quarkus.oidc.client.Tokens;
import io.smallrye.mutiny.Uni;

/**
 * Lazily initialized {@link OidcClient} used when the OIDC metadata discovery fails on the application startup.
 * If the discovery fails when any of the {@link OidcClient} methods is invoked, we return a {@link Uni} failure.
 */
final class LazyOidcClient implements OidcClient {

    private final Uni<OidcClient> deferredOidcClient;
    private volatile OidcClient resolvedOidcClient;

    LazyOidcClient(Uni<OidcClient> deferredOidcClient) {
        this.deferredOidcClient = deferredOidcClient;
        this.resolvedOidcClient = null;
    }

    @Override
    public Uni<Tokens> getTokens() {
        return runWithOidcClient(OidcClient::getTokens);
    }

    @Override
    public Uni<Tokens> getTokens(Map<String, String> additionalGrantParameters) {
        return runWithOidcClient(oidcClient -> oidcClient.getTokens(additionalGrantParameters));
    }

    @Override
    public Uni<Tokens> refreshTokens(String refreshToken) {
        return runWithOidcClient(oidcClient -> oidcClient.refreshTokens(refreshToken));
    }

    @Override
    public Uni<Tokens> refreshTokens(String refreshToken, Map<String, String> additionalGrantParameters) {
        return runWithOidcClient(oidcClient -> oidcClient.refreshTokens(refreshToken, additionalGrantParameters));
    }

    @Override
    public Uni<Boolean> revokeAccessToken(String accessToken) {
        return runWithOidcClient(oidcClient -> oidcClient.revokeAccessToken(accessToken));
    }

    @Override
    public Uni<Boolean> revokeAccessToken(String accessToken, Map<String, String> additionalParameters) {
        return runWithOidcClient(oidcClient -> oidcClient.revokeAccessToken(accessToken, additionalParameters));
    }

    @Override
    public void close() throws IOException {
        if (resolvedOidcClient != null) {
            resolvedOidcClient.close();
        }
    }

    OidcClient getResolvedOidcClient() {
        return resolvedOidcClient;
    }

    private <T> Uni<T> runWithOidcClient(Function<OidcClient, Uni<T>> action) {
        if (resolvedOidcClient != null) {
            return action.apply(resolvedOidcClient);
        }

        return deferredOidcClient.flatMap(oidcClient -> {
            LazyOidcClient.this.resolvedOidcClient = oidcClient;
            return action.apply(oidcClient);
        });
    }
}
