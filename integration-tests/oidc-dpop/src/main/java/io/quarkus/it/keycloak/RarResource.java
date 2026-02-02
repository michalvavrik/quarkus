package io.quarkus.it.keycloak;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;

import org.eclipse.microprofile.jwt.JsonWebToken;

import io.quarkus.security.Authenticated;

@Authenticated
@Path("/rar")
public class RarResource {

    @Inject
    JsonWebToken idToken;

    @GET
    public String getJwtToken() {
        return idToken.toString();
    }

}
