package io.quarkus.keycloak.admin.client;

import javax.enterprise.context.ApplicationScoped;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.keycloak.representations.AccessTokenResponse;

import io.quarkus.keycloak.admin.client.common.spi.runtime.KeycloakAdminClientAuthorizationProvider;
import io.restassured.RestAssured;

@ApplicationScoped
public class CustomAuthZProvider implements KeycloakAdminClientAuthorizationProvider {

    @ConfigProperty(name = "keycloak.url")
    String keycloakUrl;

    @Override
    public String getAuthorization() {
        return getDukesAccessToken(keycloakUrl);
    }

    static String getDukesAccessToken(String keycloakUrl) {
        return RestAssured
                .given()
                .param("grant_type", "password")
                .param("username", "duke")
                .param("password", "dukePassword")
                .param("client_id", "quarkus-app")
                .param("client_secret", "secret")
                .when()
                .post(keycloakUrl + "/realms/quarkus/protocol/openid-connect/token")
                .as(AccessTokenResponse.class)
                .getToken();
    }
}
