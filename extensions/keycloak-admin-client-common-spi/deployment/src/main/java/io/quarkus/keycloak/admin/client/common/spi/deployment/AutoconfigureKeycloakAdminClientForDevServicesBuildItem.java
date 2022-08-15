package io.quarkus.keycloak.admin.client.common.spi.deployment;

import io.quarkus.builder.item.MultiBuildItem;

/**
 * A marker build item which tells the Quarkus Keycloak Admin Client to autoconfigure clients for
 * the Dev Services for Keycloak.
 */
public final class AutoconfigureKeycloakAdminClientForDevServicesBuildItem extends MultiBuildItem {
}
