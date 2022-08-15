package io.quarkus.oidc.runtime.providers;

import javax.inject.Inject;

import io.quarkus.keycloak.admin.client.common.spi.runtime.KeycloakAdminClientAuthorizationProvider;
import io.quarkus.oidc.AccessTokenCredential;
import io.quarkus.security.identity.SecurityIdentity;

/**
 * Make it possible for the Keycloak admin client to use access token out of the box.
 */
public class DefaultKeycloakAdminClientAuthorizationProvider implements KeycloakAdminClientAuthorizationProvider {

    @Inject
    SecurityIdentity identity;

    @Override
    public String getAuthorization() {
        AccessTokenCredential credential = identity.getCredential(AccessTokenCredential.class);
        if (credential == null) {
            return null;
        }
        return credential.getToken();
    }
}
