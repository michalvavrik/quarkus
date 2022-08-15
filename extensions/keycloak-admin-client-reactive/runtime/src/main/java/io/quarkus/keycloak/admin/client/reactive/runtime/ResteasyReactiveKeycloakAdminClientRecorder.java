package io.quarkus.keycloak.admin.client.reactive.runtime;

import java.util.function.Supplier;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;

import org.jboss.resteasy.reactive.client.impl.ClientBuilderImpl;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;

import io.quarkus.keycloak.admin.client.common.AuthMethod;
import io.quarkus.keycloak.admin.client.common.KeycloakAdminClientConfig;
import io.quarkus.keycloak.admin.client.common.KeycloakAdminClientFactory;
import io.quarkus.runtime.RuntimeValue;
import io.quarkus.runtime.annotations.Recorder;

@Recorder
public class ResteasyReactiveKeycloakAdminClientRecorder {

    private final KeycloakAdminClientFactory<Keycloak> keycloakAdminClientFactory;

    public ResteasyReactiveKeycloakAdminClientRecorder(
            RuntimeValue<KeycloakAdminClientConfig> keycloakAdminClientConfigRuntimeValue) {
        this.keycloakAdminClientFactory = new KeycloakAdminClientFactory<>(keycloakAdminClientConfigRuntimeValue) {
            @Override
            protected KeycloakAdminClientFactory<Keycloak>.AbstractKeycloakBuilder builder() {
                final KeycloakBuilder keycloakBuilder = KeycloakBuilder.builder();
                return new AbstractKeycloakBuilder() {
                    @Override
                    protected Keycloak build() {
                        return keycloakBuilder.build();
                    }

                    @Override
                    protected KeycloakAdminClientFactory<Keycloak>.AbstractKeycloakBuilder serverUrl(String url) {
                        keycloakBuilder.serverUrl(url);
                        return this;
                    }

                    @Override
                    protected KeycloakAdminClientFactory<Keycloak>.AbstractKeycloakBuilder clientId(String clientId) {
                        keycloakBuilder.clientId(clientId);
                        return this;
                    }

                    @Override
                    protected KeycloakAdminClientFactory<Keycloak>.AbstractKeycloakBuilder clientSecret(String clientSecret) {
                        keycloakBuilder.clientSecret(clientSecret);
                        return this;
                    }

                    @Override
                    protected KeycloakAdminClientFactory<Keycloak>.AbstractKeycloakBuilder scope(String scope) {
                        keycloakBuilder.scope(scope);
                        return this;
                    }

                    @Override
                    protected KeycloakAdminClientFactory<Keycloak>.AbstractKeycloakBuilder grantType(String grantType) {
                        keycloakBuilder.grantType(grantType);
                        return this;
                    }

                    @Override
                    protected KeycloakAdminClientFactory<Keycloak>.AbstractKeycloakBuilder password(String password) {
                        keycloakBuilder.password(password);
                        return this;
                    }

                    @Override
                    protected KeycloakAdminClientFactory<Keycloak>.AbstractKeycloakBuilder username(String username) {
                        keycloakBuilder.username(username);
                        return this;
                    }

                    @Override
                    protected KeycloakAdminClientFactory<Keycloak>.AbstractKeycloakBuilder realm(String realm) {
                        keycloakBuilder.realm(realm);
                        return this;
                    }

                    @Override
                    protected KeycloakAdminClientFactory<Keycloak>.AbstractKeycloakBuilder authorization(String authorization) {
                        keycloakBuilder.authorization(authorization);
                        return this;
                    }
                };
            }
        };
    }

    public void setClientProvider(boolean insecure) {
        if (insecure) {
            Keycloak.setClientProvider(new ResteasyReactiveClientProvider() {

                private final HostnameVerifier noopHostnameVerifier = new HostnameVerifier() {
                    @Override
                    public boolean verify(String hostname, SSLSession session) {
                        // essentially turns hostname verification off
                        return true;
                    }
                };

                @Override
                protected ClientBuilderImpl newClientBuilder() {
                    return (ClientBuilderImpl) super.newClientBuilder()
                            .trustAll(true)
                            .hostnameVerifier(noopHostnameVerifier);
                }
            });
        } else {
            Keycloak.setClientProvider(new ResteasyReactiveClientProvider());
        }
    }

    public Supplier<Keycloak> createAdminClientBean(String clientName, AuthMethod authMethod, String authZProviderClassName) {
        return keycloakAdminClientFactory.newInstance(clientName, authMethod, authZProviderClassName);
    }

    public Supplier<Keycloak> createDefaultDevServicesBean() {
        return keycloakAdminClientFactory.newInstance();
    }
}
