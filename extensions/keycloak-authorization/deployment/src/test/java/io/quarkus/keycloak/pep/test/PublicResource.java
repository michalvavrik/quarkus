package io.quarkus.keycloak.pep.test;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.keycloak.representations.AccessTokenResponse;

import io.restassured.RestAssured;

@Path("/api/public")
public class PublicResource {

    @Inject
    @ConfigProperty(name = "keycloak.url")
    String keycloakUrl;

    @Path("/serve")
    @GET
    public String serve() {
        return "serve";
    }

    @Path("/access-token")
    @GET
    public String accessToken(String userName) {
        return RestAssured
                .given()
                .relaxedHTTPSValidation()
                .param("grant_type", "password")
                .param("username", userName)
                .param("password", userName)
                .param("client_id", "backend-service")
                .param("client_secret", "secret")
                .when()
                .post(keycloakUrl + "/realms/quarkus/protocol/openid-connect/token")
                .as(AccessTokenResponse.class).getToken();
    }
}
