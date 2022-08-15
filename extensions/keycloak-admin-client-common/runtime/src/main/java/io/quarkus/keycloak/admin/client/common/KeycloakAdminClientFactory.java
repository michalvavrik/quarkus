package io.quarkus.keycloak.admin.client.common;

import static io.quarkus.keycloak.admin.client.common.KeycloakAdminClientConfig.KeycloakNamedAdminClientConfig.DEFAULT_REALM;

import java.util.Objects;
import java.util.function.Supplier;

import org.eclipse.microprofile.config.ConfigProvider;
import org.jboss.logging.Logger;

import io.quarkus.arc.Arc;
import io.quarkus.keycloak.admin.client.common.spi.runtime.KeycloakAdminClientAuthorizationProvider;
import io.quarkus.runtime.RuntimeValue;

public abstract class KeycloakAdminClientFactory<T> {

    public static final String ADMIN = "admin";
    private static final Logger LOGGER = Logger.getLogger(KeycloakAdminClientFactory.class);

    private static final Supplier<KeycloakAdminClientConfig.KeycloakNamedAdminClientConfig> DEFAULT_CONFIG_SUPPLIER = new Supplier<KeycloakAdminClientConfig.KeycloakNamedAdminClientConfig>() {
        @Override
        public KeycloakAdminClientConfig.KeycloakNamedAdminClientConfig get() {
            return KeycloakAdminClientConfig.KeycloakNamedAdminClientConfig.newInstanceWithDefaultValues();
        }
    };
    private final RuntimeValue<KeycloakAdminClientConfig> keycloakAdminClientConfigRuntimeValue;
    private volatile String oidcServerUrl = null;
    private volatile boolean searchForOidcServerUrl = true;

    protected KeycloakAdminClientFactory(
            RuntimeValue<KeycloakAdminClientConfig> keycloakAdminClientConfigRuntimeValue) {
        this.keycloakAdminClientConfigRuntimeValue = keycloakAdminClientConfigRuntimeValue;
    }

    public Supplier<T> newInstance(String clientName, AuthMethod authMethod, String authZProviderClassName) {
        final var clientRuntimeConfig = getClientConfig(clientName);

        // Keycloak can authorize either by authZ provider (supplying token directly)
        // or by credentials (username + password + client id / client id + client secret)
        if (authZProviderClassName != null) {
            // client using authorization token

            LOGGER.tracef("Creating Keycloak admin client '%s' using authorization token.", clientName);
            final var keycloakBuilder = builder()
                    .serverUrl(getServerUrl(clientRuntimeConfig, clientName))
                    .realm(clientRuntimeConfig.realm);
            final var authZProviderClass = loadClass(clientName, authZProviderClassName);
            return new Supplier<>() {
                @Override
                public T get() {
                    try (var instanceHandle = Arc.container().instance(authZProviderClass)) {
                        if (instanceHandle.isAvailable()) {
                            // get auth token
                            final String authorization = ((KeycloakAdminClientAuthorizationProvider) instanceHandle.get())
                                    .getAuthorization();

                            if (authorization == null) {
                                throw new KeycloakAdminClientException(clientName,
                                        "Token provided by the '" + authZProviderClassName + "' is null");
                            }

                            try {
                                return keycloakBuilder.authorization(authorization).build();
                            } catch (Exception e) {
                                // typically this is going to be validation exception
                                throw new KeycloakAdminClientException(clientName, e.getMessage());
                            }
                        } else {
                            throw new KeycloakAdminClientException(clientName,
                                    "KeycloakAdminClientAuthorizationProvider implementation '" + authZProviderClassName
                                            + "' is not a bean");
                        }
                    }
                }
            };
        } else {
            // client using client credentials or password grant type

            // KeycloakBuilder also validates inputs (our config properties) when build() is called
            // but that validation is done when the request scoped bean is created
            // and sooner the validation is done, better.
            if (authMethod == AuthMethod.PASSWORD) {
                if (clientRuntimeConfig.password.isEmpty() || clientRuntimeConfig.username.isEmpty()
                        || clientRuntimeConfig.clientId.isEmpty()) {
                    throw new KeycloakAdminClientException(clientName,
                            "grant type 'password' requires username, password and client id");
                }
            } else {
                if (clientRuntimeConfig.clientId.isEmpty() || clientRuntimeConfig.clientSecret.isEmpty()) {
                    throw new KeycloakAdminClientException(clientName,
                            "grant type 'client_credentials' requires client id and secret");
                }
            }

            LOGGER.tracef("Creating Keycloak admin client '%s' using % grant type.", clientName, authMethod.grantType());
            return newInstance(builder()
                    .serverUrl(getServerUrl(clientRuntimeConfig, clientName))
                    .clientId(clientRuntimeConfig.clientId.orElse(null))
                    .clientSecret(clientRuntimeConfig.clientSecret.orElse(null))
                    .scope(clientRuntimeConfig.scope.orElse(null))
                    .grantType(authMethod.grantType())
                    .password(clientRuntimeConfig.password.orElse(null))
                    .username(clientRuntimeConfig.username.orElse(null))
                    .realm(clientRuntimeConfig.realm), clientName);
        }
    }

    /**
     * Supplies Keycloak for the administrator in the master realm. Credentials are assumed from
     * default set up of Dev Services for Keycloak. If user changed `KEYCLOAK_ADMIN_PASSWORD` or `KEYCLOAK_ADMIN`, he
     * must also configure the client himself.
     */
    public Supplier<T> newInstance() {
        return newInstance(builder()
                .serverUrl(getServerUrl(null, ADMIN))
                .clientId("admin-cli")
                .grantType(AuthMethod.PASSWORD.grantType())
                .password(ADMIN)
                .username(ADMIN)
                .realm(DEFAULT_REALM), ADMIN);
    }

    protected abstract AbstractKeycloakBuilder builder();

    private Supplier<T> newInstance(AbstractKeycloakBuilder builder, String clientName) {
        return new Supplier<>() {
            @Override
            public T get() {
                try {
                    return builder.build();
                } catch (Exception e) {
                    // typically this is going to be validation exception
                    throw new KeycloakAdminClientException(clientName, e.getMessage());
                }
            }
        };
    }

    private KeycloakAdminClientConfig.KeycloakNamedAdminClientConfig getClientConfig(String clientName) {
        // it's possible that client config won't be present as only property shared among auth methods is server url,
        // and we can take server url from the 'quarkus.oidc.auth-server-url' (if present)
        return Objects.requireNonNullElseGet(
                keycloakAdminClientConfigRuntimeValue.getValue().namedAdminClients.get(clientName),
                DEFAULT_CONFIG_SUPPLIER);
    }

    private Class<?> loadClass(String clientName, String authZProviderClassName) {
        try {
            return Class.forName(authZProviderClassName, false, Thread.currentThread().getContextClassLoader());
        } catch (ClassNotFoundException e) {
            throw new KeycloakAdminClientException(clientName, e.getMessage());
        }
    }

    private String getServerUrl(KeycloakAdminClientConfig.KeycloakNamedAdminClientConfig clientConfig,
            String clientName) {
        // first try to use the server url set in the Keycloak admin client config
        if (clientConfig != null && clientConfig.serverUrl.isPresent()) {
            return clientConfig.serverUrl.get();
        }

        // if missing, look up the Quarkus OIDC 'auth-server-url' and use its origin
        if (searchForOidcServerUrl) {
            oidcServerUrl = ConfigProvider
                    .getConfig()
                    .getOptionalValue("quarkus.oidc.auth-server-url", String.class)
                    // keep just the URL origin
                    .map(url -> url.indexOf(47, 8) != -1 ? url.substring(0, url.indexOf(47, 8)) : url)
                    .orElse(null);
            searchForOidcServerUrl = false;
        }

        // require server url
        if (oidcServerUrl == null) {
            throw new KeycloakAdminClientException(clientName, "server url not found");
        }

        return oidcServerUrl;
    }

    protected abstract class AbstractKeycloakBuilder {

        protected abstract T build();

        protected abstract AbstractKeycloakBuilder serverUrl(String url);

        protected abstract AbstractKeycloakBuilder clientId(String clientId);

        protected abstract AbstractKeycloakBuilder clientSecret(String clientSecret);

        protected abstract AbstractKeycloakBuilder scope(String scope);

        protected abstract AbstractKeycloakBuilder grantType(String grantType);

        protected abstract AbstractKeycloakBuilder password(String password);

        protected abstract AbstractKeycloakBuilder username(String username);

        protected abstract AbstractKeycloakBuilder realm(String realm);

        protected abstract AbstractKeycloakBuilder authorization(String authorization);

    }

    public static final class KeycloakAdminClientException extends RuntimeException {

        private KeycloakAdminClientException(String clientName, String message) {
            super(String.format("Failed to create Keycloak admin client '%s': %s.", clientName, message));
        }

    }

}
