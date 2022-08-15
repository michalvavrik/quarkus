package io.quarkus.keycloak.admin.client.reactive.validation;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.keycloak.admin.client.common.KeycloakAdminClientCommonProcessor;
import io.quarkus.keycloak.admin.client.common.spi.runtime.KeycloakAdminClientAuthorizationProvider;
import io.quarkus.test.QuarkusUnitTest;

/**
 * Makes sure an exception is thrown when AuthZ provider does not implement
 * {@link KeycloakAdminClientAuthorizationProvider}.0
 */
public class AuthZProviderImplementorValidationFailureTest {

    @RegisterExtension
    final static QuarkusUnitTest app = new QuarkusUnitTest()
            .withApplicationRoot(jar -> jar
                    .addClasses(WrongCustomAuthZProvider.class)
                    .addAsResource(new StringAsset("quarkus.keycloak.admin-client.\"ronald\".auth-method=AUTH_TOKEN\n" +
                            "quarkus.keycloak.admin-client.\"ronald\".authorization-provider=io.quarkus.keycloak.admin.client.reactive.validation.WrongCustomAuthZProvider\n"
                            +
                            // disable Dev Services for Keycloak as we don't need them here
                            "quarkus.keycloak.devservices.enabled=false\n" +
                            "quarkus.oidc.auth-server-url=http://ignored:8080\n"),
                            "application.properties"))
            .assertException(t -> {
                Throwable e = t;
                KeycloakAdminClientCommonProcessor.KeycloakAdminClientAuthorizationProviderException kcEx = null;
                while (e != null) {
                    if (e instanceof KeycloakAdminClientCommonProcessor.KeycloakAdminClientAuthorizationProviderException) {
                        kcEx = (KeycloakAdminClientCommonProcessor.KeycloakAdminClientAuthorizationProviderException) e;
                        break;
                    }
                    e = e.getCause();
                }
                assertNotNull(kcEx);
                final String msg = kcEx.getMessage();
                assertTrue(msg.contains("WrongCustomAuthZProvider"), msg);
                assertTrue(msg.contains("does not implement"), msg);
                assertTrue(msg.contains("KeycloakAdminClientAuthorizationProvider"), msg);
            });

    @Test
    public void test() {
        Assertions.fail();
    }

}
