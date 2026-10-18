package io.quarkus.security.test;

import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusExtensionTest;
import io.restassured.RestAssured;

/**
 * The first realm added to the security domain is its default realm, the only realm that authenticates a user name
 * and password unless a {@code RealmMapper} bean is provided. The embedded realm is added before the properties file
 * realm.
 */
class DefaultRealmTest {

    @RegisterExtension
    static final QuarkusExtensionTest config = new QuarkusExtensionTest()
            .withApplicationRoot((jar) -> jar
                    .addClasses(TestApplication.class, ParametrizedPathsResource.class)
                    .addAsResource("test-users.properties")
                    .addAsResource("test-roles.properties")
                    .addAsResource(new StringAsset("""
                            quarkus.security.users.file.enabled=true
                            quarkus.security.users.file.realm-name=file-realm
                            quarkus.security.users.file.users=test-users.properties
                            quarkus.security.users.file.roles=test-roles.properties
                            quarkus.security.users.file.plain-text=true
                            quarkus.security.users.embedded.enabled=true
                            quarkus.security.users.embedded.realm-name=embedded-realm
                            quarkus.security.users.embedded.plain-text=true
                            quarkus.security.users.embedded.users.emb=embpw
                            quarkus.security.users.embedded.roles.emb=user
                            """), "application.properties"));

    @Test
    void testEmbeddedRealmIsTheDefaultRealm() {
        RestAssured.given().auth().preemptive().basic("emb", "embpw")
                .when().get("/jaxrs-secured/parameterized-paths/my/banking/view").then()
                .statusCode(200);
        // the properties file realm is part of the domain but no realm mapper routes the request to it
        RestAssured.given().auth().preemptive().basic("stuart", "test")
                .when().get("/jaxrs-secured/parameterized-paths/my/banking/view").then()
                .statusCode(401);
    }
}
