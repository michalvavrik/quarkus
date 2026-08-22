package io.quarkus.security.test.permissionsallowed.checker;

import static io.quarkus.security.test.utils.IdentityMock.USER;
import static io.quarkus.security.test.utils.SecurityTestUtils.assertFailureFor;
import static io.quarkus.security.test.utils.SecurityTestUtils.assertSuccess;

import java.util.Set;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.security.ForbiddenException;
import io.quarkus.security.PermissionChecker;
import io.quarkus.security.PermissionsAllowed;
import io.quarkus.security.StringPermission;
import io.quarkus.security.test.utils.AuthData;
import io.quarkus.security.test.utils.IdentityMock;
import io.quarkus.security.test.utils.SecurityTestUtils;
import io.quarkus.test.QuarkusExtensionTest;

/**
 * Tests the interaction between escaped colons in {@code @PermissionsAllowed} values
 * and {@code @PermissionChecker} matching.
 * <p>
 * Key design: {@code @PermissionChecker} matching uses raw (un-parsed) string comparison.
 * The escape-aware parsing only runs when no checker matches the raw value.
 */
public class EscapedColonPermissionCheckerTest {

    private static final AuthData USER_WITH_AUGMENTORS = new AuthData(USER, true);

    @RegisterExtension
    static final QuarkusExtensionTest config = new QuarkusExtensionTest()
            .withApplicationRoot((jar) -> jar
                    .addClasses(IdentityMock.class, AuthData.class, SecurityTestUtils.class));

    @Inject
    SecuredBean bean;

    @Test
    public void checkerMatchesRawEscapedValue() {
        // @PermissionsAllowed("org\\:acme\\:service") with @PermissionChecker("org\\:acme\\:service")
        // The raw strings match -> checker handles authorization, no parsing
        assertSuccess(() -> bean.rawCheckerMatch(true), "rawCheckerMatch", USER_WITH_AUGMENTORS);
        assertFailureFor(() -> bean.rawCheckerMatch(false), ForbiddenException.class, USER_WITH_AUGMENTORS);

        // Identity permission cannot grant access when checker exists
        var userWithPerm = new AuthData(USER, true, new StringPermission("org:acme:service"));
        assertFailureFor(() -> bean.rawCheckerMatch(false), ForbiddenException.class, userWithPerm);
    }

    @Test
    public void backwardsCompatCheckerWithColon() {
        // @PermissionsAllowed("read:write") with @PermissionChecker("read:write")
        // Existing behavior: raw strings match, checker handles it, no splitting
        assertSuccess(() -> bean.backwardsCompatChecker(true), "backwardsCompatChecker", USER_WITH_AUGMENTORS);
        assertFailureFor(() -> bean.backwardsCompatChecker(false), ForbiddenException.class, USER_WITH_AUGMENTORS);
    }

    @Test
    public void checkerDoesNotMatchDifferentEscaping() {
        // @PermissionsAllowed("ns\\:perm") — raw string is "ns\:perm"
        // No @PermissionChecker("ns\\:perm") exists
        // Falls through to parsing: name="ns:perm", no action
        // Access granted only by identity permission
        var userWithPerm = new AuthData(Set.of("user"), false, "user",
                Set.of(new StringPermission("ns:perm")), true);
        assertSuccess(() -> bean.noCheckerEscapedFallthrough(), "noCheckerEscapedFallthrough", userWithPerm);

        // Without identity permission, access denied
        assertFailureFor(() -> bean.noCheckerEscapedFallthrough(), ForbiddenException.class, USER_WITH_AUGMENTORS);
    }

    @Test
    public void mixedCheckerAndEscapedParsed() {
        // @PermissionsAllowed({"scope:read", "scope\\:admin\\:read"})
        // "scope:read" -> exact match with @PermissionChecker("scope:read")
        // "scope\:admin\:read" -> no checker match, parsed to name="scope:admin:read", no action
        // One-of semantics: either the checker grants or the identity permission grants

        // Checker grants access
        assertSuccess(() -> bean.mixedCheckerAndParsed(true), "mixedCheckerAndParsed", USER_WITH_AUGMENTORS);

        // Checker denies but identity permission for the escaped name grants
        var userWithPerm = new AuthData(Set.of("user"), false, "user",
                Set.of(new StringPermission("scope:admin:read")), true);
        assertSuccess(() -> bean.mixedCheckerAndParsed(false), "mixedCheckerAndParsed", userWithPerm);

        // Both deny
        assertFailureFor(() -> bean.mixedCheckerAndParsed(false), ForbiddenException.class, USER_WITH_AUGMENTORS);

        // Identity permission for "scope" with action "read" should NOT grant access
        // because "scope:read" is handled exclusively by the checker
        var userWithSplitPerm = new AuthData(Set.of("user"), false, "user",
                Set.of(new StringPermission("scope", "read")), true);
        assertFailureFor(() -> bean.mixedCheckerAndParsed(false), ForbiddenException.class, userWithSplitPerm);
    }

    @ApplicationScoped
    public static class SecuredBean {

        // raw value "org\:acme\:service" matches @PermissionChecker("org\:acme\:service")
        @PermissionsAllowed("org\\:acme\\:service")
        String rawCheckerMatch(boolean allow) {
            return "rawCheckerMatch";
        }

        // backwards-compatible: "read:write" matches @PermissionChecker("read:write")
        @PermissionsAllowed("read:write")
        String backwardsCompatChecker(boolean allow) {
            return "backwardsCompatChecker";
        }

        // no checker for "ns\:perm" -> falls through to escape-aware parsing
        @PermissionsAllowed("ns\\:perm")
        String noCheckerEscapedFallthrough() {
            return "noCheckerEscapedFallthrough";
        }

        // "scope:read" has a checker; "scope\:admin\:read" does not
        @PermissionsAllowed({ "scope:read", "scope\\:admin\\:read" })
        String mixedCheckerAndParsed(boolean scopeRead) {
            return "mixedCheckerAndParsed";
        }
    }

    @ApplicationScoped
    public static class PermissionCheckers {

        @PermissionChecker("org\\:acme\\:service")
        boolean canAccessOrgAcmeService(boolean allow) {
            return allow;
        }

        @PermissionChecker("read:write")
        boolean canReadWrite(boolean allow) {
            return allow;
        }

        @PermissionChecker("scope:read")
        boolean canScopeRead(boolean scopeRead) {
            return scopeRead;
        }
    }
}
