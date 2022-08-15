package io.quarkus.it.keycloak;

import java.io.IOException;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.event.Observes;
import javax.inject.Inject;

import org.jboss.resteasy.reactive.client.impl.ClientBuilderImpl;
import org.keycloak.admin.client.Keycloak;

import io.quarkus.keycloak.admin.client.reactive.runtime.ResteasyReactiveClientProvider;
import io.quarkus.oidc.runtime.OidcConfig;
import io.quarkus.runtime.StartupEvent;

@ApplicationScoped
public class RegisterSecuredClientProvider {

    @Inject
    OidcConfig oidcConfig;

    void onStart(@Observes StartupEvent ev) {
        // use client provider with trust store and key store
        Keycloak.setClientProvider(new ResteasyReactiveClientProvider() {

            @Override
            protected ClientBuilderImpl newClientBuilder() {
                return (ClientBuilderImpl) super.newClientBuilder()
                        .trustStore(loadKeystore(oidcConfig.defaultTenant.tls.trustStoreFile.orElseThrow(),
                                oidcConfig.defaultTenant.tls.trustStorePassword.orElseThrow()))
                        .keyStore(
                                loadKeystore(oidcConfig.defaultTenant.tls.keyStoreFile.orElseThrow(),
                                        oidcConfig.defaultTenant.tls.keyStorePassword),
                                oidcConfig.defaultTenant.tls.keyStorePassword);
            }

            private KeyStore loadKeystore(Path keystorePath, String password) {
                try {
                    // client-truststore.jks -> jks
                    final String extension = keystorePath.toString().split("\\.")[1];
                    final KeyStore keyStore = KeyStore.getInstance(extension);
                    try (var is = RegisterSecuredClientProvider.class.getResourceAsStream("/" + keystorePath)) {
                        keyStore.load(is, password.toCharArray());
                    }
                    return keyStore;
                } catch (IOException | NoSuchAlgorithmException | CertificateException | KeyStoreException e) {
                    throw new RuntimeException(e);
                }
            }
        });
    }

}
