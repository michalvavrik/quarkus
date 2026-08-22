package io.quarkus.vertx.http.security;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.runtime.configuration.ConfigurationException;
import io.quarkus.test.QuarkusExtensionTest;

/**
 * Verifies that HTTP security policy permission values with multiple unescaped colons
 * cause a startup error.
 */
public class HttpPermissionMultipleColonsValidationFailureTest {

    @RegisterExtension
    static final QuarkusExtensionTest test = new QuarkusExtensionTest()
            .withApplicationRoot((jar) -> jar
                    .addAsResource(new StringAsset(
                            "quarkus.http.auth.basic=true\n"
                                    + "quarkus.http.auth.policy.bad.roles-allowed=test\n"
                                    + "quarkus.http.auth.policy.bad.permissions.test=system:role:query1\n"
                                    + "quarkus.http.auth.permission.bad.paths=/test/bad\n"
                                    + "quarkus.http.auth.permission.bad.policy=bad\n"),
                            "application.properties"))
            .assertException(t -> {
                Throwable e = t;
                ConfigurationException ce = null;
                while (e != null) {
                    if (e instanceof ConfigurationException) {
                        ce = (ConfigurationException) e;
                        break;
                    }
                    e = e.getCause();
                }
                assertNotNull(ce, "Expected ConfigurationException but got: " + t);
                assertTrue(ce.getMessage().contains("system:role:query1"),
                        "Error should reference the invalid value: " + ce.getMessage());
                assertTrue(
                        ce.getMessage().contains("Invalid permission format")
                                || ce.getMessage().contains("separator"),
                        "Error should mention the separator issue: " + ce.getMessage());
            });

    @Test
    public void test() {
        Assertions.fail();
    }
}
