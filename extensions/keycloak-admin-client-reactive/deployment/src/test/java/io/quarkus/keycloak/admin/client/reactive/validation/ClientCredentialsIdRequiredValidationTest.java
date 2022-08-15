package io.quarkus.keycloak.admin.client.reactive.validation;

import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusUnitTest;

public class ClientCredentialsIdRequiredValidationTest {

    @RegisterExtension
    final static QuarkusUnitTest app = new QuarkusUnitTest()
            .withApplicationRoot(jar -> jar
                    .addAsResource(
                            new StringAsset("quarkus.keycloak.admin-client.\"client-missing-id\".client-secret=secret\n" +
                                    "quarkus.keycloak.admin-client.\"client-missing-id\".auth-method=CLIENT_CREDENTIALS\n" +
                                    // disable Dev Services for Keycloak as we don't need them here
                                    "quarkus.keycloak.devservices.enabled=false\n" +
                                    "quarkus.oidc.auth-server-url=http://ignored:8080\n"),
                            "application.properties"))
            .assertException(new ExceptionAssertor("client id"));

    @Test
    public void test() {
        Assertions.fail();
    }

}
