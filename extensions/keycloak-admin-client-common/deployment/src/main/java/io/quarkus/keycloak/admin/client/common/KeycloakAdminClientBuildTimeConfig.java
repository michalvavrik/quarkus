package io.quarkus.keycloak.admin.client.common;

import java.util.Map;
import java.util.Optional;

import io.quarkus.keycloak.admin.client.common.spi.runtime.KeycloakAdminClientAuthorizationProvider;
import io.quarkus.runtime.annotations.ConfigDocMapKey;
import io.quarkus.runtime.annotations.ConfigDocSection;
import io.quarkus.runtime.annotations.ConfigGroup;
import io.quarkus.runtime.annotations.ConfigItem;
import io.quarkus.runtime.annotations.ConfigPhase;
import io.quarkus.runtime.annotations.ConfigRoot;

/**
 * Keycloak Admin Client
 */
@ConfigRoot(phase = ConfigPhase.BUILD_TIME, name = "keycloak.admin-client")
public class KeycloakAdminClientBuildTimeConfig {

    /**
     * If the Dev Services For Keycloak are running and there are no `named-admin-clients` specified,
     * we create default client `admin`. You can achieve same result with following properties in place:
     * <code>
     * quarkus.keycloak.admin-client."admin".username=admin
     * quarkus.keycloak.admin-client."admin".password=admin
     * quarkus.keycloak.admin-client."admin".client-id=admin-cli
     * quarkus.keycloak.admin-client."admin".auth-method=PASSWORD
     * </code>
     * The autoconfiguration can be disabled with this property.
     */
    @ConfigItem(defaultValue = "true", name = "devservices.enabled")
    public boolean devServicesEnabled;

    /**
     * Keycloak Admin Client
     */
    @ConfigDocSection
    @ConfigDocMapKey("admin-client-name")
    @ConfigItem(name = ConfigItem.PARENT)
    public Map<String, KeycloakNamedAdminClientBuildTimeConfig> namedAdminClients;

    @ConfigGroup
    public static class KeycloakNamedAdminClientBuildTimeConfig {

        /**
         * You can either provide authentication token directly via `authorization-provider`,
         * or follow a pattern of a grant type:
         * - set `PASSWORD` for the `password` grant type
         * - set `CLIENT_CREDENTIALS` for the `client_credentials` grant type
         */
        @ConfigItem
        public AuthMethod authMethod;

        /**
         * The fully qualified name of the bean class that implements
         * {@link KeycloakAdminClientAuthorizationProvider}.
         * If you use the Quarkus OIDC with a Keycloak Server, then default authorization provider is set up for you.
         * The default provider uses access token from the request for authentication.
         */
        @ConfigItem(defaultValueDocumentation = "io.quarkus.oidc.runtime.providers.DefaultKeycloakAdminClientAuthorizationProvider (only with the Quarkus OIDC)")
        public Optional<String> authorizationProvider;

    }

}
