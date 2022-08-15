package io.quarkus.keycloak.admin.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;

import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.idm.RealmRepresentation;

import io.quarkus.test.QuarkusDevModeTest;
import io.restassured.RestAssured;

public class AutoconfigurationForKeycloakDevServicesTest {

    // Keycloak admin client autoconfigure the client for the Keycloak "admin" user when Keycloak Dev Services
    // are running and user specified no client at all
    @RegisterExtension
    final static QuarkusDevModeTest app = new QuarkusDevModeTest()
            .withApplicationRoot(jar -> jar.addClasses(AdminResource.class));

    @Test
    public void testGetRealms() {
        final var getRealmsReq = RestAssured.given().get("/api/admin/realms");
        assertEquals(200, getRealmsReq.statusCode());
        final var realms = Arrays.asList(getRealmsReq.as(RealmRepresentation[].class));
        assertTrue(realms.size() >= 2);
        assertTrue(realms.stream().anyMatch(rr -> "quarkus".equals(rr.getRealm())));
        assertTrue(realms.stream().anyMatch(rr -> "master".equals(rr.getRealm())));
    }

    @Path("/api/admin")
    public static class AdminResource {

        @Inject
        Keycloak keycloak;

        @GET
        @Path("/realms")
        public RealmRepresentation[] getRealms() {
            return keycloak.realms().findAll().toArray(new RealmRepresentation[] {});
        }

    }

}
