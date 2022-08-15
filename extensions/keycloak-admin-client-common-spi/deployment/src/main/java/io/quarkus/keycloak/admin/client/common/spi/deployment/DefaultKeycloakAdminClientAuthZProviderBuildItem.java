package io.quarkus.keycloak.admin.client.common.spi.deployment;

import io.quarkus.builder.item.SimpleBuildItem;
import io.quarkus.keycloak.admin.client.common.spi.runtime.KeycloakAdminClientAuthorizationProvider;

/**
 * Registers default {@link KeycloakAdminClientAuthorizationProvider} used when no custom authorization provider has been
 * provided.
 */
public final class DefaultKeycloakAdminClientAuthZProviderBuildItem extends SimpleBuildItem {

    private final Class<? extends KeycloakAdminClientAuthorizationProvider> defaultAuthZProvider;

    public DefaultKeycloakAdminClientAuthZProviderBuildItem(
            Class<? extends KeycloakAdminClientAuthorizationProvider> defaultAuthZProvider) {
        this.defaultAuthZProvider = defaultAuthZProvider;
    }

    public Class<? extends KeycloakAdminClientAuthorizationProvider> getDefaultAuthZProvider() {
        return defaultAuthZProvider;
    }
}
