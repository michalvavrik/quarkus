package io.quarkus.oidc.state.manager.db;

import io.quarkus.oidc.AuthorizationCodeTokens;
import io.quarkus.oidc.OidcRequestContext;
import io.quarkus.oidc.OidcTenantConfig;
import io.quarkus.oidc.TokenStateManager;
import io.smallrye.mutiny.Uni;
import io.vertx.ext.web.RoutingContext;
import jakarta.inject.Inject;
import org.hibernate.reactive.mutiny.Mutiny;

public class DbTokenStateManager implements TokenStateManager {

    @Inject
    Mutiny.SessionFactory sessionFactory;

    DbTokenStateManager() {
        // FIXME: Mutiny periodical database delete postponed randomly
        // FIXME: delete if timestamp is smaller than now
        // FIXME: iff it is enabled
    }

    @Override
    public Uni<String> createTokenState(RoutingContext routingContext, OidcTenantConfig oidcConfig,
                                        AuthorizationCodeTokens tokens, OidcRequestContext<String> requestContext) {
        // FIXME: determine TTL from route attribute + 30 sec
        // FIXME: generate random session key

        return null;
    }

    @Override
    public Uni<AuthorizationCodeTokens> getTokens(RoutingContext routingContext, OidcTenantConfig oidcConfig, String tokenState, OidcRequestContext<AuthorizationCodeTokens> requestContext) {
        // FIXME:
        return null;
    }

    @Override
    public Uni<Void> deleteTokens(RoutingContext routingContext, OidcTenantConfig oidcConfig, String tokenState, OidcRequestContext<Void> requestContext) {
        return null;
    }

}
