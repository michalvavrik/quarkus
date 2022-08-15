package io.quarkus.keycloak.admin.client.common;

import java.util.function.BooleanSupplier;

public class UserConfiguredNamedAdminClients implements BooleanSupplier {

    KeycloakAdminClientBuildTimeConfig keycloakAdminClientBuildTimeConfig;

    @Override
    public boolean getAsBoolean() {
        return !keycloakAdminClientBuildTimeConfig.namedAdminClients.isEmpty();
    }
}