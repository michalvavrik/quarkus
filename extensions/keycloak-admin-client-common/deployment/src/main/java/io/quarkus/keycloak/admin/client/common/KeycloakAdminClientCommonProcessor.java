package io.quarkus.keycloak.admin.client.common;

import static io.quarkus.keycloak.admin.client.common.AuthMethod.AUTH_TOKEN;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.jboss.jandex.ClassInfo;
import org.jboss.jandex.DotName;
import org.jboss.jandex.IndexView;
import org.jboss.logging.Logger;

import io.quarkus.keycloak.admin.client.common.spi.runtime.KeycloakAdminClientAuthorizationProvider;

public final class KeycloakAdminClientCommonProcessor {

    private static final Logger LOGGER = Logger.getLogger(KeycloakAdminClientCommonProcessor.class);

    public static AuthZProvidersAnalysis collectAuthZProviders(
            Map<String, KeycloakAdminClientBuildTimeConfig.KeycloakNamedAdminClientBuildTimeConfig> namedAdminClients,
            Class<? extends KeycloakAdminClientAuthorizationProvider> defaultAuthZProviderClass) {

        final String defaultAuthZProviderClassName;
        if (defaultAuthZProviderClass != null) {
            defaultAuthZProviderClassName = defaultAuthZProviderClass.getName();
            LOGGER.tracef("Found default authorization provider '%s'.", defaultAuthZProviderClassName);
        } else {
            defaultAuthZProviderClassName = null;
        }

        final Set<String> unremovableBeansClassNames = new HashSet<>();
        final Map<String, String> clientNameToAuthZProviderClassName = new HashMap<>();
        final Set<String> visited = new HashSet<>();
        for (var nameToClientConfig : namedAdminClients.entrySet()) {
            final String clientName = nameToClientConfig.getKey();
            final var clientConfig = nameToClientConfig.getValue();
            if (clientConfig.authMethod == AUTH_TOKEN) {

                // use default authorization provider if the 'authorization-provider' property is null
                final String authZProviderClassName = clientConfig.authorizationProvider.orElse(defaultAuthZProviderClassName);

                // must have the authorization provider
                if (authZProviderClassName == null || authZProviderClassName.isEmpty()) {
                    throw new KeycloakAdminClientAuthorizationProviderException(clientName,
                            "configuration property 'authorization-provider' is missing and default authorization provider is not available");
                }

                // collect authorization providers in map: client name -> authorization provider class name
                clientNameToAuthZProviderClassName.put(clientName, authZProviderClassName);

                // only register as an unremovable once
                // the default authorization provider is already unremovable (see below)
                if (!visited.add(authZProviderClassName) || authZProviderClassName.equals(defaultAuthZProviderClassName)) {
                    continue;
                }

                // make the authorization provider unremovable as it's accessed via Arc.container.instance()
                unremovableBeansClassNames.add(authZProviderClassName);
            }
        }

        // register the default authorization provider as a RequestScoped bean iff the provider was used
        if (defaultAuthZProviderClassName != null && visited.contains(defaultAuthZProviderClassName)) {
            return new AuthZProvidersAnalysis(defaultAuthZProviderClass, unremovableBeansClassNames,
                    clientNameToAuthZProviderClassName);
        }

        return new AuthZProvidersAnalysis(null, unremovableBeansClassNames, clientNameToAuthZProviderClassName);
    }

    public static void validateAuthZProviders(Map<String, String> clientNameToAuthZProviderClassName, IndexView indexView) {
        for (Map.Entry<String, String> entry : clientNameToAuthZProviderClassName
                .entrySet()) {
            final String authZProviderClassName = entry.getValue();
            final String clientName = entry.getKey();

            // the authorization provider class must exist
            final ClassInfo authZProviderClassInfo = indexView.getClassByName(DotName.createSimple(authZProviderClassName));
            if (authZProviderClassInfo == null) {
                throw new KeycloakAdminClientAuthorizationProviderException(clientName,
                        " the authorization provider class '" + authZProviderClassName
                                + "' was not found. Please use the fully qualified name of the bean class");
            }

            // the authorization provider must implement KeycloakAdminClientAuthorizationProvider
            boolean notFound = true;
            for (DotName interfaceName : authZProviderClassInfo.interfaceNames()) {
                if (interfaceName.toString().equals(KeycloakAdminClientAuthorizationProvider.class.getName())) {
                    notFound = false;
                    break;
                }
            }
            if (notFound) {
                throw new KeycloakAdminClientAuthorizationProviderException(clientName,
                        "the authorization provider class '" + authZProviderClassName + "' does not implement "
                                + KeycloakAdminClientAuthorizationProvider.class.getName());
            }
        }
    }

    public static final class AuthZProvidersAnalysis {

        public final Class<? extends KeycloakAdminClientAuthorizationProvider> defaultAuthZProviderClass;
        public final Set<String> unremovableBeansClassNames;
        public final Map<String, String> clientNameToAuthZProviderClassName;

        private AuthZProvidersAnalysis(Class<? extends KeycloakAdminClientAuthorizationProvider> defaultAuthZProviderClass,
                Set<String> unremovableBeansClassNames, Map<String, String> clientNameToAuthZProviderClassName) {
            this.defaultAuthZProviderClass = defaultAuthZProviderClass;
            this.unremovableBeansClassNames = unremovableBeansClassNames;
            this.clientNameToAuthZProviderClassName = clientNameToAuthZProviderClassName;
        }

    }

    public static final class KeycloakAdminClientAuthorizationProviderException extends RuntimeException {

        private KeycloakAdminClientAuthorizationProviderException(String clientName, String message) {
            super(String.format("Keycloak admin client '%s' is using authorization provider, but %s.", clientName, message));
        }
    }
}
