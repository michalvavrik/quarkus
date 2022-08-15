package io.quarkus.keycloak.admin.client.reactive.validation;

import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusUnitTest;

public class PwdGrantTypeUsernameRequiredValidationTest {

    @RegisterExtension
    final static QuarkusUnitTest app = new QuarkusUnitTest()
            .withApplicationRoot(jar -> jar
                    .addAsResource(
                            new StringAsset("quarkus.keycloak.admin-client.\"duke-missing-username\".password=dukePassword\n" +
                                    "quarkus.keycloak.admin-client.\"duke-missing-username\".client-id=quarkus-app\n" +
                                    "quarkus.keycloak.admin-client.\"duke-missing-username\".auth-method=PASSWORD\n" +
                                    // disable Dev Services for Keycloak as we don't need them here
                                    "quarkus.keycloak.devservices.enabled=false\n" +
                                    "quarkus.oidc.auth-server-url=http://ignored:8080\n"),
                            "application.properties"))
            .assertException(new ExceptionAssertor("username"));

    @Test
    public void test() {
        Assertions.fail();
    }

}
