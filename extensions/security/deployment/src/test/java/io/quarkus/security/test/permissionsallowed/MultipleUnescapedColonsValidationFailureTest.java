package io.quarkus.security.test.permissionsallowed;

import jakarta.inject.Singleton;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.security.PermissionsAllowed;
import io.quarkus.test.QuarkusExtensionTest;

/**
 * Verifies that {@code @PermissionsAllowed} values with multiple unescaped colons
 * cause a build-time error. Only one unescaped colon (the separator) is allowed.
 */
public class MultipleUnescapedColonsValidationFailureTest {

    @RegisterExtension
    static final QuarkusExtensionTest config = new QuarkusExtensionTest()
            .assertException(t -> {
                Assertions.assertEquals(RuntimeException.class, t.getClass(), t.getMessage());
                Assertions.assertTrue(t.getMessage().contains("system:role:query1"),
                        "Error should reference the invalid value: " + t.getMessage());
                Assertions.assertTrue(
                        t.getMessage().contains("more than one") || t.getMessage().contains("separator"),
                        "Error should mention the separator issue: " + t.getMessage());
            });

    @Test
    public void test() {
        Assertions.fail();
    }

    @Singleton
    public static class SecuredBean {

        @PermissionsAllowed("system:role:query1")
        public void securedMethod() {
        }
    }
}
