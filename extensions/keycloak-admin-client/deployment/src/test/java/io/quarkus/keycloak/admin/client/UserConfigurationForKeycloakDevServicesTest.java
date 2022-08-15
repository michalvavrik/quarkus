package io.quarkus.keycloak.admin.client;

import static io.quarkus.keycloak.admin.client.CustomAuthZProvider.getDukesAccessToken;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.function.Function;

import javax.inject.Inject;
import javax.inject.Named;
import javax.ws.rs.GET;
import javax.ws.rs.Path;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;

import io.quarkus.security.Authenticated;
import io.quarkus.test.QuarkusDevModeTest;
import io.restassured.RestAssured;
import io.restassured.response.Response;

public class UserConfigurationForKeycloakDevServicesTest {

    static final String REALM_NAME = "quarkus";

    @RegisterExtension
    final static QuarkusDevModeTest app = new QuarkusDevModeTest()
            .withApplicationRoot(jar -> jar
                    .addClasses(AdminResource.class, CustomAuthZProvider.class)
                    .addAsResource("app-dev-mode-user-config.properties", "application.properties"));

    @Test
    public void testGetRoles() {
        // use 'password' grant type
        final Response getRolesReq = RestAssured.given().get("/api/admin/roles");
        assertEquals(200, getRolesReq.statusCode());
        final List<RoleRepresentation> roles = getRolesReq.jsonPath().getList(".", RoleRepresentation.class);
        assertNotNull(roles);
        // assert there are roles admin and user (among others)
        assertTrue(roles.stream().anyMatch(rr -> "user".equals(rr.getName())));
        assertTrue(roles.stream().anyMatch(rr -> "admin".equals(rr.getName())));
    }

    @Test
    public void testGetUsers() {
        // use custom authorization provider
        final Response getUsersReq = RestAssured.given().get("/api/admin/users");
        assertEquals(200, getUsersReq.statusCode());
        final List<UserRepresentation> users = getUsersReq.jsonPath().getList(".", UserRepresentation.class);
        assertNotNull(users);
        // assert duke is in response
        assertTrue(users.stream().anyMatch(ur -> "duke".equals(ur.getUsername())));
    }

    @Test
    public void testGetRealm() {
        // use default authorization provider (here provided by the Quarkus OIDC extension)
        RestAssured.given().auth().oauth2(getDukesAccessToken(RestAssured.get("/api/admin/keycloak-url").asString()))
                .get("/api/admin/realm").then().statusCode(200).body("realm", is(REALM_NAME));
    }

    @Test
    public void testGetClients() {
        // hot reload, initially, credentials are incorrect
        RestAssured.given().get("/api/admin/clients").then().statusCode(500);

        // correct credentials
        app.modifyResourceFile("application.properties", new Function<String, String>() {
            @Override
            public String apply(String s) {
                return s.replaceAll("hazard", "duke");
            }
        });

        // should succeed now
        final Response getClientsReq = RestAssured.given().get("/api/admin/clients");
        assertEquals(200, getClientsReq.statusCode());
        final List<ClientRepresentation> clientRepresentations = getClientsReq.jsonPath().getList(".",
                ClientRepresentation.class);
        assertTrue(clientRepresentations.stream().anyMatch(cr -> "quarkus-app".equals(cr.getClientId())));
        assertTrue(clientRepresentations.stream().anyMatch(cr -> "admin-cli".equals(cr.getClientId())));
    }

    @Path("/api/admin")
    public static class AdminResource {

        @Named("duke-pwd")
        @Inject
        Keycloak keycloakPwd;

        @Named("duke-authz-provider")
        @Inject
        Keycloak keycloakDukeAuthZProvider;

        @Named("default-authz-provider")
        @Inject
        Keycloak keycloakDefaultAuthZProvider;

        @Named("duke-hot-reload")
        Keycloak keycloakHotReload;

        @ConfigProperty(name = "keycloak.url")
        String keycloakUrl;

        @GET
        @Path("/roles")
        public List<RoleRepresentation> getRoles() {
            return keycloakPwd.realm(REALM_NAME).roles().list();
        }

        @GET
        @Path("/users")
        public List<UserRepresentation> getUsers() {
            return keycloakDukeAuthZProvider.realm(REALM_NAME).users().list();
        }

        @Authenticated
        @GET
        @Path("/realm")
        public RealmRepresentation getRealm() {
            return keycloakDefaultAuthZProvider.realm(REALM_NAME).toRepresentation();
        }

        @GET
        @Path("/clients")
        public List<ClientRepresentation> getClients() {
            return keycloakHotReload.realm(REALM_NAME).clients().findAll();
        }

        @GET
        @Path("/keycloak-url")
        public String getKeycloakUrl() {
            return keycloakUrl;
        }

    }

}
