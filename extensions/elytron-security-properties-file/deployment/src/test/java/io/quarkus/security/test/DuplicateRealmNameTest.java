package io.quarkus.security.test;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.logging.Level;

import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusExtensionTest;
import io.restassured.RestAssured;

/**
 * Elytron only supports one realm per realm name: when two realms share a realm name, the realm added last to the
 * security domain replaces the other one and the build logs a warning. The embedded realm is added before the
 * properties file realm, so the properties file realm wins here.
 */
class DuplicateRealmNameTest {

    @RegisterExtension
    static final QuarkusExtensionTest config = new QuarkusExtensionTest()
            .withApplicationRoot((jar) -> jar
                    .addClasses(TestApplication.class, ParametrizedPathsResource.class)
                    .addAsResource("test-users.properties")
                    .addAsResource("test-roles.properties")
                    .addAsResource(new StringAsset("""
                            quarkus.security.users.file.enabled=true
                            quarkus.security.users.file.users=test-users.properties
                            quarkus.security.users.file.roles=test-roles.properties
                            quarkus.security.users.file.plain-text=true
                            quarkus.security.users.embedded.enabled=true
                            quarkus.security.users.embedded.plain-text=true
                            quarkus.security.users.embedded.users.emb=embpw
                            quarkus.security.users.embedded.roles.emb=user
                            """), "application.properties"))
            .setLogRecordPredicate(record -> record.getLevel().intValue() >= Level.WARNING.intValue()
                    && record.getMessage() != null && record.getMessage().contains("is used by both"))
            .assertLogRecords(records -> assertTrue(records.stream()
                    .anyMatch(record -> record.getParameters() != null && record.getParameters().length > 0
                            && "Quarkus".equals(record.getParameters()[0])),
                    "Expected a warning about the duplicate realm name 'Quarkus'"));

    @Test
    void testRealmAddedLastWins() {
        // the properties file realm replaces the embedded realm, which was added to the domain first
        RestAssured.given().auth().preemptive().basic("stuart", "test")
                .when().get("/jaxrs-secured/parameterized-paths/my/banking/view").then()
                .statusCode(200);
        RestAssured.given().auth().preemptive().basic("emb", "embpw")
                .when().get("/jaxrs-secured/parameterized-paths/my/banking/view").then()
                .statusCode(401);
    }
}
