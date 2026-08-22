package io.quarkus.security.test.permissionsallowed;

import static io.quarkus.security.test.utils.SecurityTestUtils.assertFailureFor;
import static io.quarkus.security.test.utils.SecurityTestUtils.assertSuccess;

import java.util.Set;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.security.ForbiddenException;
import io.quarkus.security.PermissionsAllowed;
import io.quarkus.security.StringPermission;
import io.quarkus.security.test.utils.AuthData;
import io.quarkus.security.test.utils.IdentityMock;
import io.quarkus.security.test.utils.SecurityTestUtils;
import io.quarkus.test.QuarkusExtensionTest;

class EscapedColonPermissionsAllowedTest {

    private static final String EC = "\\:";
    private static final String EB = "\\\\";

    @RegisterExtension
    static final QuarkusExtensionTest config = new QuarkusExtensionTest()
            .withApplicationRoot((jar) -> jar
                    .addClasses(IdentityMock.class, AuthData.class, SecurityTestUtils.class));

    @Inject
    SecuredBean bean;

    @Test
    void escapedColonsInNameNoAction() {
        var userWithPerm = new AuthData(Set.of("user"), false, "user",
                Set.of(new StringPermission("system:role:query1")), true);
        assertSuccess(() -> bean.escapedColonNameOnly(), "escapedColonNameOnly", userWithPerm);

        var userWithWrongPerm = new AuthData(Set.of("user"), false, "user",
                Set.of(new StringPermission("system")), true);
        assertFailureFor(() -> bean.escapedColonNameOnly(), ForbiddenException.class, userWithWrongPerm);

        var userWithPartialName = new AuthData(Set.of("user"), false, "user",
                Set.of(new StringPermission("system", "role:query1")), true);
        assertFailureFor(() -> bean.escapedColonNameOnly(), ForbiddenException.class, userWithPartialName);
    }

    @Test
    void escapedColonInNameWithAction() {
        var userWithPerm = new AuthData(Set.of("user"), false, "user",
                Set.of(new StringPermission("system:role", "query")), true);
        assertSuccess(() -> bean.escapedColonNameWithAction(), "escapedColonNameWithAction", userWithPerm);

        var userNameOnly = new AuthData(Set.of("user"), false, "user",
                Set.of(new StringPermission("system:role")), true);
        assertFailureFor(() -> bean.escapedColonNameWithAction(), ForbiddenException.class, userNameOnly);

        var userWrongSplit = new AuthData(Set.of("user"), false, "user",
                Set.of(new StringPermission("system", "role")), true);
        assertFailureFor(() -> bean.escapedColonNameWithAction(), ForbiddenException.class, userWrongSplit);
    }

    @Test
    void escapedColonInAction() {
        var userWithPerm = new AuthData(Set.of("user"), false, "user",
                Set.of(new StringPermission("perm", "role:query")), true);
        assertSuccess(() -> bean.escapedColonInAction(), "escapedColonInAction", userWithPerm);

        var userPartialAction = new AuthData(Set.of("user"), false, "user",
                Set.of(new StringPermission("perm", "role")), true);
        assertFailureFor(() -> bean.escapedColonInAction(), ForbiddenException.class, userPartialAction);
    }

    @Test
    void escapedBackslashBeforeSeparator() {
        var userWithPerm = new AuthData(Set.of("user"), false, "user",
                Set.of(new StringPermission("read\\", "write")), true);
        assertSuccess(() -> bean.escapedBackslashBeforeSeparator(), "escapedBackslashBeforeSeparator", userWithPerm);
    }

    @Test
    void mixedEscapedAndPlainValues() {
        var userEscaped = new AuthData(Set.of("user"), false, "user",
                Set.of(new StringPermission("system:role:query1")), true);
        assertSuccess(() -> bean.mixedValues(), "mixedValues", userEscaped);

        var userSimple = new AuthData(Set.of("user"), false, "user",
                Set.of(new StringPermission("simple")), true);
        assertSuccess(() -> bean.mixedValues(), "mixedValues", userSimple);

        var userWithAction = new AuthData(Set.of("user"), false, "user",
                Set.of(new StringPermission("name", "action")), true);
        assertSuccess(() -> bean.mixedValues(), "mixedValues", userWithAction);

        var userWrong = new AuthData(Set.of("user"), false, "user",
                Set.of(new StringPermission("system")), true);
        assertFailureFor(() -> bean.mixedValues(), ForbiddenException.class, userWrong);
    }

    @Test
    void inclusiveWithEscapedColons() {
        var userWithBoth = new AuthData(Set.of("user"), false, "user",
                Set.of(new StringPermission("system:role", "read"), new StringPermission("system:role")), true);
        assertSuccess(() -> bean.inclusiveEscaped(), "inclusiveEscaped", userWithBoth);

        var userWithAction = new AuthData(Set.of("user"), false, "user",
                Set.of(new StringPermission("system:role", "read")), true);
        assertSuccess(() -> bean.inclusiveEscaped(), "inclusiveEscaped", userWithAction);

        var userNoAction = new AuthData(Set.of("user"), false, "user",
                Set.of(new StringPermission("system:role")), true);
        assertFailureFor(() -> bean.inclusiveEscaped(), ForbiddenException.class, userNoAction);
    }

    @ApplicationScoped
    public static class SecuredBean {

        @PermissionsAllowed("system" + EC + "role" + EC + "query1")
        String escapedColonNameOnly() {
            return "escapedColonNameOnly";
        }

        @PermissionsAllowed("system" + EC + "role:query")
        String escapedColonNameWithAction() {
            return "escapedColonNameWithAction";
        }

        @PermissionsAllowed("perm:role" + EC + "query")
        String escapedColonInAction() {
            return "escapedColonInAction";
        }

        @PermissionsAllowed("read" + EB + ":write")
        String escapedBackslashBeforeSeparator() {
            return "escapedBackslashBeforeSeparator";
        }

        @PermissionsAllowed({ "system" + EC + "role" + EC + "query1", "simple", "name:action" })
        String mixedValues() {
            return "mixedValues";
        }

        @PermissionsAllowed(value = { "system" + EC + "role", "system" + EC + "role:read" }, inclusive = true)
        String inclusiveEscaped() {
            return "inclusiveEscaped";
        }
    }
}
