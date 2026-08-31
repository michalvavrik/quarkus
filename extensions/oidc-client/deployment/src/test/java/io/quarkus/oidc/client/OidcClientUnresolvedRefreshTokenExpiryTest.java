package io.quarkus.oidc.client;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;

import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.oidc.client.runtime.TokensHelper;
import io.quarkus.test.QuarkusExtensionTest;

class OidcClientUnresolvedRefreshTokenExpiryTest {

    @RegisterExtension
    static final QuarkusExtensionTest test = new QuarkusExtensionTest()
            .withApplicationRoot(jar -> jar.addClasses(
                    TokensResource.class,
                    MockTokenEndpoint.class))
            .withConfiguration("""
                    quarkus.keycloak.devservices.enabled=false
                    quarkus.oidc.enabled=false
                    """)
            .withRuntimeConfiguration("""
                    quarkus.oidc-client.auth-server-url=http://localhost:8081
                    quarkus.oidc-client.discovery-enabled=false
                    quarkus.oidc-client.token-path=/mock-oidc/token
                    quarkus.oidc-client.client-id=test-client
                    quarkus.oidc-client.credentials.secret=test-secret
                    quarkus.oidc-client.grant.type=client
                    quarkus.oidc-client.absolute-expires-in=true

                    quarkus.oidc-client.resolved.auth-server-url=http://localhost:8081
                    quarkus.oidc-client.resolved.discovery-enabled=false
                    quarkus.oidc-client.resolved.token-path=/mock-oidc/token
                    quarkus.oidc-client.resolved.client-id=test-client
                    quarkus.oidc-client.resolved.credentials.secret=test-secret
                    quarkus.oidc-client.resolved.grant.type=client
                    quarkus.oidc-client.resolved.absolute-expires-in=true
                    quarkus.oidc-client.resolved.grant.refresh-expires-in-property=refresh_token_expires_in
                    """);

    @Test
    void testExpiredRefreshTokenUsedWhenExpiryNotResolved() {
        given()
                .get("/tokens/default")
                .then()
                .statusCode(200)
                .body(containsString("failed:"))
                .body(containsString("invalid_grant"));
    }

    @Test
    void testNewTokensAcquiredWhenRefreshExpiryResolved() {
        given()
                .get("/tokens/resolved")
                .then()
                .statusCode(200)
                .body(is("acquired:test-access-token"));
    }

    @Path("/tokens")
    public static class TokensResource {

        @Inject
        OidcClients clients;

        @GET
        @Path("/default")
        @Produces(MediaType.TEXT_PLAIN)
        public String defaultClient() {
            return acquireTokens(clients.getClient());
        }

        @GET
        @Path("/resolved")
        @Produces(MediaType.TEXT_PLAIN)
        public String resolvedClient() {
            return acquireTokens(clients.getClient("resolved"));
        }

        private static String acquireTokens(OidcClient client) {
            TokensHelper helper = new TokensHelper();
            helper.initTokens(client);
            try {
                Tokens tokens = helper.getTokens(client).await().indefinitely();
                return "acquired:" + tokens.getAccessToken();
            } catch (OidcClientException e) {
                return "failed:" + e.getMessage();
            }
        }
    }

    @Path("/mock-oidc/token")
    public static class MockTokenEndpoint {

        @POST
        @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
        @Produces(MediaType.APPLICATION_JSON)
        public Response token(@FormParam("grant_type") String grantType) {
            if ("refresh_token".equals(grantType)) {
                return Response.status(400)
                        .entity("{\"error\":\"invalid_grant\",\"error_description\":\"refresh token expired\"}")
                        .build();
            }
            return Response.ok("""
                    {
                        "access_token": "test-access-token",
                        "token_type": "Bearer",
                        "expires_in": 1,
                        "refresh_token": "opaque-refresh-token",
                        "refresh_token_expires_in": 1
                    }
                    """).build();
        }
    }
}
