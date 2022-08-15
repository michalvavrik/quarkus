package io.quarkus.it.keycloak;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.List;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.keycloak.representations.idm.RealmRepresentation;

import io.quarkus.test.junit.QuarkusTest;

@QuarkusTest
public class AdminClientTestCase {

    @Test
    public void testGetExistingRealm() {
        // use password grant type
        RealmRepresentation realm = given()
                .when().get("/admin-client/realm").as(RealmRepresentation.class);
        assertEquals("quarkus", realm.getRealm());
    }

    @Test
    public void testGetNewRealm() {
        // use password grant type
        RealmRepresentation realm = given()
                .when().get("/admin-client/newrealm").as(RealmRepresentation.class);
        assertEquals("quarkus2", realm.getRealm());
    }

    @Test
    public void testGetRealmRoles() {
        // use client credentials grant type
        given().when().get("/admin-client/realm-roles").then().statusCode(200)
                .body(Matchers.containsString("confidential"))
                .body(Matchers.containsString("superuser"))
                .body(Matchers.containsString("user"))
                .body(Matchers.containsString("admin"))
                .body("$.size()", Matchers.greaterThanOrEqualTo(7));
    }

    @Test
    public void testGetRealmNames() {
        // use client credentials grant type
        final List<String> realmNames = Arrays.asList(given().when().get("/admin-client/realm-names").as(String[].class));
        assertTrue(realmNames.contains("quarkus"));
        assertTrue(realmNames.contains("master"));
    }
}
