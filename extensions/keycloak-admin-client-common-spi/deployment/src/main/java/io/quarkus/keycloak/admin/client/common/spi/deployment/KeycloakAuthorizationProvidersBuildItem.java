package io.quarkus.keycloak.admin.client.common.spi.deployment;

import java.util.Map;

import io.quarkus.builder.item.SimpleBuildItem;

public final class KeycloakAuthorizationProvidersBuildItem extends SimpleBuildItem {

    private final Map<String, String> clientNameToAuthZProviderClassName;

    public KeycloakAuthorizationProvidersBuildItem(Map<String, String> clientNameToAuthZProviderClassName) {
        this.clientNameToAuthZProviderClassName = clientNameToAuthZProviderClassName;
    }

    public Map<String, String> getClientNameToAuthZProviderClassName() {
        return clientNameToAuthZProviderClassName;
    }
}
