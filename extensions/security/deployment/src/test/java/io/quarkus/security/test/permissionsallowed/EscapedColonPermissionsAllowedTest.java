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

/**
 * Tests that escaped colons in {@code @PermissionsAllowed} values are handled correctly
 * when using {@link StringPermission} (no {@code @PermissionChecker}).
 * <p>
 * Escape rules:
 * <ul>
 * <li>{@code \:} — literal colon (not a separator)</li>
 * <li>{@code \\} — literal backslash</li>
 * <li>Unescaped {@code :} — separator between permission name and action</li>
 * </ul>
 * In Java source, {@code \} is written as {@code \\}, so:
 * <ul>
 * <li>{@code "system\\:role"} in source = string {@code system\:role} = escaped colon</li>
 * <li>{@code "system\\\\:role"} in source = string {@code system\\:role} = escaped backslash + separator</li>
 * </ul>
 */
public class EscapedColonPermissionsAllowedTest {

    @RegisterExtension
    static final QuarkusExtensionTest config = new QuarkusExtensionTest()
            .withApplicationRoot((jar) -> jar
                    .addClasses(IdentityMock.class, AuthData.class, SecurityTestUtils.class));

    @Inject
    SecuredBean bean;

    @Test
    public void escapedColonsInNameNoAction() {
        // @PermissionsAllowed("system\\:role\\:query1") -> name="system:role:query1", no action
        // Identity must have StringPermission("system:role:query1") to get access
        var userWithPerm = new AuthData(Set.of("user"), false, "user",
                Set.of(new StringPermission("system:role:query1")), true);
        assertSuccess(() -> bean.escapedColonNameOnly(), "escapedColonNameOnly", userWithPerm);

        // Wrong permission name should be denied
        var userWithWrongPerm = new AuthData(Set.of("user"), false, "user",
                Set.of(new StringPermission("system")), true);
        assertFailureFor(() -> bean.escapedColonNameOnly(), ForbiddenException.class, userWithWrongPerm);

        // Without the colon escaping, "system" alone should not grant access
        var userWithPartialName = new AuthData(Set.of("user"), false, "user",
                Set.of(new StringPermission("system", "role:query1")), true);
        assertFailureFor(() -> bean.escapedColonNameOnly(), ForbiddenException.class, userWithPartialName);
    }

    @Test
    public void escapedColonInNameWithAction() {
        // @PermissionsAllowed("system\\:role:query") -> name="system:role", action="query"
        // Identity needs StringPermission("system:role", "query")
        var userWithPerm = new AuthData(Set.of("user"), false, "user",
                Set.of(new StringPermission("system:role", "query")), true);
        assertSuccess(() -> bean.escapedColonNameWithAction(), "escapedColonNameWithAction", userWithPerm);

        // Name without action should be denied
        var userNameOnly = new AuthData(Set.of("user"), false, "user",
                Set.of(new StringPermission("system:role")), true);
        assertFailureFor(() -> bean.escapedColonNameWithAction(), ForbiddenException.class, userNameOnly);

        // Wrong split (unescaped parse) should be denied
        var userWrongSplit = new AuthData(Set.of("user"), false, "user",
                Set.of(new StringPermission("system", "role")), true);
        assertFailureFor(() -> bean.escapedColonNameWithAction(), ForbiddenException.class, userWrongSplit);
    }

    @Test
    public void escapedColonInAction() {
        // @PermissionsAllowed("perm:role\\:query") -> name="perm", action="role:query"
        var userWithPerm = new AuthData(Set.of("user"), false, "user",
                Set.of(new StringPermission("perm", "role:query")), true);
        assertSuccess(() -> bean.escapedColonInAction(), "escapedColonInAction", userWithPerm);

        // Only first action part should be denied
        var userPartialAction = new AuthData(Set.of("user"), false, "user",
                Set.of(new StringPermission("perm", "role")), true);
        assertFailureFor(() -> bean.escapedColonInAction(), ForbiddenException.class, userPartialAction);
    }

    @Test
    public void escapedBackslashBeforeSeparator() {
        // @PermissionsAllowed("read\\\\:write") -> string "read\\:write"
        // \\=literal backslash, :=separator -> name="read\", action="write"
        var userWithPerm = new AuthData(Set.of("user"), false, "user",
                Set.of(new StringPermission("read\\", "write")), true);
        assertSuccess(() -> bean.escapedBackslashBeforeSeparator(), "escapedBackslashBeforeSeparator", userWithPerm);
    }

    @Test
    public void mixedEscapedAndPlainValues() {
        // @PermissionsAllowed({"system\\:role\\:query1", "simple", "name:action"})
        // One-of semantics: any of the three should grant access

        // Escaped name grants access
        var userEscaped = new AuthData(Set.of("user"), false, "user",
                Set.of(new StringPermission("system:role:query1")), true);
        assertSuccess(() -> bean.mixedValues(), "mixedValues", userEscaped);

        // Simple name grants access
        var userSimple = new AuthData(Set.of("user"), false, "user",
                Set.of(new StringPermission("simple")), true);
        assertSuccess(() -> bean.mixedValues(), "mixedValues", userSimple);

        // Name:action grants access
        var userWithAction = new AuthData(Set.of("user"), false, "user",
                Set.of(new StringPermission("name", "action")), true);
        assertSuccess(() -> bean.mixedValues(), "mixedValues", userWithAction);

        // Wrong permission denied
        var userWrong = new AuthData(Set.of("user"), false, "user",
                Set.of(new StringPermission("system")), true);
        assertFailureFor(() -> bean.mixedValues(), ForbiddenException.class, userWrong);
    }

    @Test
    public void inclusiveWithEscapedColons() {
        // @PermissionsAllowed(value = {"system\\:role", "system\\:role:read"}, inclusive = true)
        // Inclusive: ALL must be satisfied
        // "system\:role" -> name="system:role", no action
        // "system\:role:read" -> name="system:role", action="read"
        // Both map to permission name "system:role" — one with no action, one with action "read"

        // Has both permissions -> granted
        var userWithBoth = new AuthData(Set.of("user"), false, "user",
                Set.of(new StringPermission("system:role", "read"), new StringPermission("system:role")), true);
        assertSuccess(() -> bean.inclusiveEscaped(), "inclusiveEscaped", userWithBoth);

        // StringPermission("system:role", "read") implies StringPermission("system:role")
        // because StringPermission with actions implies one without actions if name matches
        var userWithAction = new AuthData(Set.of("user"), false, "user",
                Set.of(new StringPermission("system:role", "read")), true);
        assertSuccess(() -> bean.inclusiveEscaped(), "inclusiveEscaped", userWithAction);

        // Missing the action -> denied (inclusive requires both)
        var userNoAction = new AuthData(Set.of("user"), false, "user",
                Set.of(new StringPermission("system:role")), true);
        assertFailureFor(() -> bean.inclusiveEscaped(), ForbiddenException.class, userNoAction);
    }

    @ApplicationScoped
    public static class SecuredBean {

        // "system\:role\:query1" -> name="system:role:query1", no action
        @PermissionsAllowed("system\\:role\\:query1")
        String escapedColonNameOnly() {
            return "escapedColonNameOnly";
        }

        // "system\:role:query" -> name="system:role", action="query"
        @PermissionsAllowed("system\\:role:query")
        String escapedColonNameWithAction() {
            return "escapedColonNameWithAction";
        }

        // "perm:role\:query" -> name="perm", action="role:query"
        @PermissionsAllowed("perm:role\\:query")
        String escapedColonInAction() {
            return "escapedColonInAction";
        }

        // "read\\:write" -> \\=escaped backslash, :=separator -> name="read\", action="write"
        @PermissionsAllowed("read\\\\:write")
        String escapedBackslashBeforeSeparator() {
            return "escapedBackslashBeforeSeparator";
        }

        // Mix of escaped and plain values (one-of semantics)
        @PermissionsAllowed({ "system\\:role\\:query1", "simple", "name:action" })
        String mixedValues() {
            return "mixedValues";
        }

        // Inclusive: all must be satisfied
        @PermissionsAllowed(value = { "system\\:role", "system\\:role:read" }, inclusive = true)
        String inclusiveEscaped() {
            return "inclusiveEscaped";
        }
    }
}
