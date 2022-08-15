package io.quarkus.it.keycloak;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.inject.Named;

import org.keycloak.admin.client.Keycloak;

import io.quarkus.keycloak.admin.client.common.spi.runtime.KeycloakAdminClientAuthorizationProvider;

@ApplicationScoped
public class AdminClientAuthZProvider implements KeycloakAdminClientAuthorizationProvider {

    @Named("admin")
    @Inject
    Keycloak keycloak;

    @Override
    public String getAuthorization() {
        // here goes business logic behind access token retrieval
        // we use another Keycloak instance for convenience
        return keycloak.tokenManager().getAccessTokenString();
    }
}
