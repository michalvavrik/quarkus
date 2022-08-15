package io.quarkus.keycloak.admin.client.common.spi.runtime;

/**
 * Provides auth token for the Keycloak admin client.
 */
public interface KeycloakAdminClientAuthorizationProvider {

    /**
     * @return Keycloak auth token
     */
    String getAuthorization();
}
