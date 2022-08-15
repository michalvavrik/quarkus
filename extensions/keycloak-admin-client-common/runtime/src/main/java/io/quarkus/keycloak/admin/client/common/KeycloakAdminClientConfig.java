package io.quarkus.keycloak.admin.client.common;

import java.util.Map;
import java.util.Optional;

import io.quarkus.runtime.annotations.ConfigDocMapKey;
import io.quarkus.runtime.annotations.ConfigDocSection;
import io.quarkus.runtime.annotations.ConfigGroup;
import io.quarkus.runtime.annotations.ConfigItem;
import io.quarkus.runtime.annotations.ConfigPhase;
import io.quarkus.runtime.annotations.ConfigRoot;

@ConfigRoot(phase = ConfigPhase.RUN_TIME, name = "keycloak.admin-client")
public class KeycloakAdminClientConfig {

    /**
     * Keycloak Admin Client
     */
    @ConfigDocSection
    @ConfigDocMapKey("admin-client-name")
    @ConfigItem(name = ConfigItem.PARENT)
    public Map<String, KeycloakNamedAdminClientConfig> namedAdminClients;

    @ConfigGroup
    public static class KeycloakNamedAdminClientConfig {

        public static final String DEFAULT_REALM = "master";

        /**
         * Realm.
         */
        @ConfigItem(defaultValue = DEFAULT_REALM)
        public String realm;

        /**
         * Keycloak server URL, for example, `https://host:port`.
         */
        @ConfigItem(defaultValueDocumentation = "origin of the ${quarkus.oidc.auth-server-url} (if the Quarkus OIDC extension is present)")
        public Optional<String> serverUrl;

        /**
         * Client id.
         */
        @ConfigItem
        public Optional<String> clientId;

        /**
         * Client secret.
         */
        @ConfigItem
        public Optional<String> username;

        /**
         * Password used with a `password` grant type.
         */
        @ConfigItem
        public Optional<String> password;

        /**
         * Username used for with a `password` grant type.
         */
        @ConfigItem
        public Optional<String> clientSecret;

        /**
         * OAuth 2.0 <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-3.3">Access Token Scope</a>.
         */
        @ConfigItem
        public Optional<String> scope;

        private KeycloakNamedAdminClientConfig withDefaultValues() {
            realm = DEFAULT_REALM;
            scope = Optional.empty();
            clientSecret = Optional.empty();
            password = Optional.empty();
            username = Optional.empty();
            clientId = Optional.empty();
            serverUrl = Optional.empty();
            return this;
        }

        static KeycloakNamedAdminClientConfig newInstanceWithDefaultValues() {
            return new KeycloakNamedAdminClientConfig().withDefaultValues();
        }

    }

}
