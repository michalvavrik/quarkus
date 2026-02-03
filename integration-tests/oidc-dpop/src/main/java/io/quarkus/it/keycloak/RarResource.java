package io.quarkus.it.keycloak;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;

import io.quarkus.oidc.AccessTokenCredential;
import io.quarkus.security.Authenticated;
import io.quarkus.security.identity.SecurityIdentity;

@Authenticated
@Path("/rar")
public class RarResource {

    @Inject
    SecurityIdentity securityIdentity;

    @GET
    public String getAccessToken() {
        var accessTokenCredential = securityIdentity.getCredential(AccessTokenCredential.class);
        return accessTokenCredential.getToken();
    }

}
