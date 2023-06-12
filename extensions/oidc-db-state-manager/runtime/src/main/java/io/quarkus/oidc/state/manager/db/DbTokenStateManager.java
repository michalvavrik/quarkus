package io.quarkus.oidc.state.manager.db;

import io.quarkus.oidc.AuthorizationCodeTokens;
import io.quarkus.oidc.OidcRequestContext;
import io.quarkus.oidc.OidcTenantConfig;
import io.quarkus.oidc.TokenStateManager;
import io.smallrye.mutiny.Uni;
import io.vertx.ext.web.RoutingContext;

public class DbTokenStateManager implements TokenStateManager {

    @Override
    public Uni<String> createTokenState(RoutingContext routingContext, OidcTenantConfig oidcConfig, AuthorizationCodeTokens tokens, OidcRequestContext<String> requestContext) {
        return null;
    }

    @Override
    public Uni<AuthorizationCodeTokens> getTokens(RoutingContext routingContext, OidcTenantConfig oidcConfig, String tokenState, OidcRequestContext<AuthorizationCodeTokens> requestContext) {
        return null;
    }

    @Override
    public Uni<Void> deleteTokens(RoutingContext routingContext, OidcTenantConfig oidcConfig, String tokenState, OidcRequestContext<Void> requestContext) {
        return null;
    }

}
