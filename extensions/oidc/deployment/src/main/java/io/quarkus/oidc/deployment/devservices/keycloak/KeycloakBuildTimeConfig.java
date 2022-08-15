package io.quarkus.oidc.deployment.devservices.keycloak;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import io.quarkus.runtime.annotations.ConfigGroup;
import io.quarkus.runtime.annotations.ConfigItem;
import io.quarkus.runtime.annotations.ConfigRoot;

/**
 * Build time configuration for OIDC.
 */
@ConfigRoot
public class KeycloakBuildTimeConfig {
    /**
     * Dev services configuration.
     */
    @ConfigItem
    public KeycloakDevServicesConfig devservices;

    @ConfigGroup
    public static class KeycloakDevServicesConfig extends DevServicesConfig {

        /**
         * The Keycloak client-level roles assigned to user. Here is how you can give `alice` right to list users and
         * roles <a href="https://www.keycloak.org/docs/latest/server_admin/#_per_realm_admin_permissions">defined</a>
         * by a built-in client called `realm-management`:
         *
         * <code>
         * quarkus.keycloak.devservices.client-roles.alice.realm-management=view-users,view-roles
         * </code>
         *
         * Client-level roles are only assignable to users created via `quarkus.keycloak.devservices.users`.
         */
        @ConfigItem
        public Map<String, Map<String, List<String>>> clientRoles;

        /**
         * Client scopes separated by comma, which will be added automatically to each created client.
         * Client scopes are only added by Dev Services for Keycloak when it creates default realm,
         * if no custom realm is imported.
         */
        @ConfigItem(defaultValue = "microprofile-jwt")
        public Optional<String> defaultClientScopes;

    }
}
