package io.quarkus.keycloak.admin.client.reactive.validation;

import javax.enterprise.context.ApplicationScoped;

import io.quarkus.keycloak.admin.client.common.spi.runtime.KeycloakAdminClientAuthorizationProvider;

/**
 * This AuthZ Provider does not implement
 * {@link KeycloakAdminClientAuthorizationProvider},
 * thus its validation should fail.
 */
@ApplicationScoped
public class WrongCustomAuthZProvider {

    public String getAuthorization() {
        return "token";
    }

}
