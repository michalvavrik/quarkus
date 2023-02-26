package io.quarkus.keycloak.pep.test;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusDevModeTest;
import io.restassured.RestAssured;

public class KeycloakAuthorizationDevServicesTest {

    @RegisterExtension
    final static QuarkusDevModeTest app = new QuarkusDevModeTest()
            .withApplicationRoot(jar -> jar
                    .addClasses(AdminResource.class, PublicResource.class, UserResource.class)
                    .addAsResource("offline-enforcer-application.properties", "application.properties")
                    .addAsResource("quarkus-realm.json"));

    @Test
    public void testNoPathMatcherRemoteCalls() {
        testPublicResource();
        testAccessUserResource();
        testAccessAdminResource();
    }

    private void testAccessUserResource() {
        RestAssured.given().auth().oauth2(getAccessToken("alice"))
                .when().get("/api/users/me")
                .then()
                .statusCode(200);
        RestAssured.given().auth().oauth2(getAccessToken("jdoe"))
                .when().get("/api/users/me")
                .then()
                .statusCode(200);
    }

    private void testAccessAdminResource() {
        RestAssured.given().auth().oauth2(getAccessToken("alice"))
                .when().get("/api/admin")
                .then()
                .statusCode(403);
        RestAssured.given().auth().oauth2(getAccessToken("jdoe"))
                .when().get("/api/admin")
                .then()
                .statusCode(403);
        RestAssured.given().auth().oauth2(getAccessToken("admin"))
                .when().get("/api/admin")
                .then()
                .statusCode(200);
    }

    private void testPublicResource() {
        RestAssured.given()
                .when().get("/api/public/serve")
                .then()
                .statusCode(200);
    }

    private String getAccessToken(String userName) {
        return RestAssured.given().body(userName)
                .get("/api/public/access-token")
                .asString();
    }
}
