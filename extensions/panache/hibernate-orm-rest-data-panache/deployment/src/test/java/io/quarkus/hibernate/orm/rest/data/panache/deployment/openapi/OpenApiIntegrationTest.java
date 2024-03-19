package io.quarkus.hibernate.orm.rest.data.panache.deployment.openapi;

import static org.hamcrest.Matchers.is;

import java.security.Permission;
import java.security.Principal;
import java.util.List;
import java.util.Map;
import java.util.Set;

import jakarta.inject.Singleton;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.builder.Version;
import io.quarkus.maven.dependency.Dependency;
import io.quarkus.security.StringPermission;
import io.quarkus.security.credential.Credential;
import io.quarkus.security.identity.IdentityProviderManager;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.test.QuarkusUnitTest;
import io.quarkus.vertx.http.runtime.security.ChallengeData;
import io.quarkus.vertx.http.runtime.security.HttpAuthenticationMechanism;
import io.restassured.RestAssured;
import io.restassured.filter.log.ResponseLoggingFilter;
import io.smallrye.mutiny.Uni;
import io.vertx.ext.web.RoutingContext;

class OpenApiIntegrationTest {

    private static final String OPEN_API_PATH = "/q/openapi";
    private static final String COLLECTIONS_SCHEMA_REF = "#/components/schemas/Collection";

    @RegisterExtension
    static final QuarkusUnitTest TEST = new QuarkusUnitTest()
            .withApplicationRoot((jar) -> jar
                    .addClasses(Collection.class, CollectionsResource.class, CollectionsRepository.class,
                            AbstractEntity.class, AbstractItem.class, Item.class, ItemsResource.class,
                            ItemsRepository.class, EmptyListItem.class, EmptyListItemsRepository.class,
                            EmptyListItemsResource.class, SecuredResource.class, CustomHttpAuthMechanism.class)
                    .addAsResource("application.properties")
                    .addAsResource("import.sql"))
            .setForcedDependencies(List.of(
                    Dependency.of("io.quarkus", "quarkus-smallrye-openapi-deployment", Version.getVersion()),
                    Dependency.of("io.quarkus", "quarkus-jdbc-h2-deployment", Version.getVersion()),
                    Dependency.of("io.quarkus", "quarkus-resteasy-jackson-deployment", Version.getVersion()),
                    Dependency.of("io.quarkus", "quarkus-security-deployment", Version.getVersion())));
    //            .setRun(true);

    @Test
    public void testOpenApiForGeneratedResources() {
        RestAssured.given().queryParam("format", "JSON")
                .log().all().filter(new ResponseLoggingFilter())
                .when().get(OPEN_API_PATH)
                .then()
                .header("Content-Type", "application/json;charset=UTF-8")
                .body("info.title", Matchers.equalTo("quarkus-hibernate-orm-rest-data-panache-deployment API"))
                .body("paths.'/collections'", Matchers.hasKey("get"))
                .body("paths.'/collections'.get.tags", Matchers.hasItem("CollectionsResource"))
                .body("paths.'/collections'.get.responses.'200'.content.'application/json'.schema.type", is("array"))
                .body("paths.'/collections'.get.responses.'200'.content.'application/json'.schema.items.$ref",
                        is(COLLECTIONS_SCHEMA_REF))
                .body("paths.'/collections'", Matchers.hasKey("post"))
                .body("paths.'/collections'.post.tags", Matchers.hasItem("CollectionsResource"))
                .body("paths.'/collections'.post.requestBody.content.'application/json'.schema.$ref",
                        is(COLLECTIONS_SCHEMA_REF))
                .body("paths.'/collections'.post.responses.'201'.content.'application/json'.schema.$ref",
                        is(COLLECTIONS_SCHEMA_REF))
                .body("paths.'/collections'.post.security[0].SecurityScheme", Matchers.hasItem("user"))
                .body("paths.'/collections/{id}'", Matchers.hasKey("get"))
                .body("paths.'/collections/{id}'.get.responses.'200'.content.'application/json'.schema.$ref",
                        is(COLLECTIONS_SCHEMA_REF))
                .body("paths.'/collections/{id}'.get.security[0].SecurityScheme", Matchers.hasItem("user"))
                .body("paths.'/collections/{id}'", Matchers.hasKey("put"))
                .body("paths.'/collections/{id}'.put.requestBody.content.'application/json'.schema.$ref",
                        is(COLLECTIONS_SCHEMA_REF))
                .body("paths.'/collections/{id}'.put.responses.'201'.content.'application/json'.schema.$ref",
                        is(COLLECTIONS_SCHEMA_REF))
                .body("paths.'/collections/{id}'.put.security[0].SecurityScheme", Matchers.hasItem("superuser"))
                .body("paths.'/collections/{id}'", Matchers.hasKey("delete"))
                .body("paths.'/collections/{id}'.delete.responses", Matchers.hasKey("204"))
                .body("paths.'/collections/{id}'.delete.security[0].SecurityScheme", Matchers.hasItem("admin"))
                .body("paths.'/empty-list-items'", Matchers.hasKey("get"))
                .body("paths.'/empty-list-items'.get.tags", Matchers.hasItem("EmptyListItemsResource"))
                .body("paths.'/empty-list-items'", Matchers.hasKey("post"))
                .body("paths.'/empty-list-items'.post.tags", Matchers.hasItem("EmptyListItemsResource"))
                .body("paths.'/empty-list-items/{id}'", Matchers.hasKey("get"))
                .body("paths.'/empty-list-items/{id}'", Matchers.hasKey("put"))
                .body("paths.'/empty-list-items/{id}'", Matchers.hasKey("delete"))
                .body("paths.'/items'", Matchers.hasKey("get"))
                .body("paths.'/items'", Matchers.hasKey("post"))
                .body("paths.'/items/{id}'", Matchers.hasKey("get"))
                .body("paths.'/items/{id}'", Matchers.hasKey("put"))
                .body("paths.'/items/{id}'", Matchers.hasKey("delete"));
    }

    @Test
    public void testEndpointsSecured() {
        RestAssured.given()
                .log().all().filter(new ResponseLoggingFilter())
                .get("/secured/count")
                .then()
                .statusCode(403);
        RestAssured.given()
                .header("authenticated", true)
                .log().all().filter(new ResponseLoggingFilter())
                .get("/secured/count")
                .then()
                .statusCode(200);
        RestAssured.given()
                .log().all().filter(new ResponseLoggingFilter())
                .get("/secured/1")
                .then()
                .statusCode(403);
        RestAssured.given()
                .header("authenticated", true)
                .log().all().filter(new ResponseLoggingFilter())
                .get("/secured/1")
                .then()
                .statusCode(200)
                .body("id", Matchers.is(1))
                .body("name", Matchers.is("first"));
    }

    @Singleton
    public static class CustomHttpAuthMechanism implements HttpAuthenticationMechanism {

        @Override
        public Uni<SecurityIdentity> authenticate(RoutingContext context, IdentityProviderManager identityProviderManager) {
            if (context.request().getHeader("authenticated") != null) {
                return Uni.createFrom().item(new SecurityIdentity() {
                    @Override
                    public Principal getPrincipal() {
                        return new Principal() {
                            @Override
                            public String getName() {
                                return "Zeebrugge";
                            }
                        };
                    }

                    @Override
                    public boolean isAnonymous() {
                        return false;
                    }

                    @Override
                    public Set<String> getRoles() {
                        return Set.of("admin");
                    }

                    @Override
                    public boolean hasRole(String s) {
                        return "admin".equals(s);
                    }

                    @Override
                    public <T extends Credential> T getCredential(Class<T> aClass) {
                        return null;
                    }

                    @Override
                    public Set<Credential> getCredentials() {
                        return Set.of();
                    }

                    @Override
                    public <T> T getAttribute(String s) {
                        return null;
                    }

                    @Override
                    public Map<String, Object> getAttributes() {
                        return Map.of();
                    }

                    @Override
                    public Uni<Boolean> checkPermission(Permission permission) {
                        return Uni.createFrom().item(new StringPermission("get").implies(permission));
                    }
                });
            }
            return Uni.createFrom().nullItem();
        }

        @Override
        public Uni<ChallengeData> getChallenge(RoutingContext context) {
            return Uni.createFrom().item(new ChallengeData(403, null, null));
        }
    }
}
