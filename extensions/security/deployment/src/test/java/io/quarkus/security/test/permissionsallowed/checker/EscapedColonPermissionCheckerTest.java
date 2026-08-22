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

class EscapedColonPermissionCheckerTest {

    private static final String EC = "\\:";

    private static final AuthData USER_WITH_AUGMENTORS = new AuthData(USER, true);

    @RegisterExtension
    static final QuarkusExtensionTest config = new QuarkusExtensionTest()
            .withApplicationRoot((jar) -> jar
                    .addClasses(IdentityMock.class, AuthData.class, SecurityTestUtils.class));

    @Inject
    SecuredBean bean;

    @Test
    void checkerMatchesRawEscapedValue() {
        assertSuccess(() -> bean.rawCheckerMatch(true), "rawCheckerMatch", USER_WITH_AUGMENTORS);
        assertFailureFor(() -> bean.rawCheckerMatch(false), ForbiddenException.class, USER_WITH_AUGMENTORS);

        var userWithPerm = new AuthData(USER, true, new StringPermission("org:acme:service"));
        assertFailureFor(() -> bean.rawCheckerMatch(false), ForbiddenException.class, userWithPerm);
    }

    @Test
    void backwardsCompatCheckerWithColon() {
        assertSuccess(() -> bean.backwardsCompatChecker(true), "backwardsCompatChecker", USER_WITH_AUGMENTORS);
        assertFailureFor(() -> bean.backwardsCompatChecker(false), ForbiddenException.class, USER_WITH_AUGMENTORS);
    }

    @Test
    void checkerDoesNotMatchDifferentEscaping() {
        var userWithPerm = new AuthData(Set.of("user"), false, "user",
                Set.of(new StringPermission("ns:perm")), true);
        assertSuccess(() -> bean.noCheckerEscapedFallthrough(), "noCheckerEscapedFallthrough", userWithPerm);

        assertFailureFor(() -> bean.noCheckerEscapedFallthrough(), ForbiddenException.class, USER_WITH_AUGMENTORS);
    }

    @Test
    void mixedCheckerAndEscapedParsed() {
        assertSuccess(() -> bean.mixedCheckerAndParsed(true), "mixedCheckerAndParsed", USER_WITH_AUGMENTORS);

        var userWithPerm = new AuthData(Set.of("user"), false, "user",
                Set.of(new StringPermission("scope:admin:read")), true);
        assertSuccess(() -> bean.mixedCheckerAndParsed(false), "mixedCheckerAndParsed", userWithPerm);

        assertFailureFor(() -> bean.mixedCheckerAndParsed(false), ForbiddenException.class, USER_WITH_AUGMENTORS);

        var userWithSplitPerm = new AuthData(Set.of("user"), false, "user",
                Set.of(new StringPermission("scope", "read")), true);
        assertFailureFor(() -> bean.mixedCheckerAndParsed(false), ForbiddenException.class, userWithSplitPerm);
    }

    @ApplicationScoped
    public static class SecuredBean {

        @PermissionsAllowed("org" + EC + "acme" + EC + "service")
        String rawCheckerMatch(boolean allow) {
            return "rawCheckerMatch";
        }

        @PermissionsAllowed("read:write")
        String backwardsCompatChecker(boolean allow) {
            return "backwardsCompatChecker";
        }

        @PermissionsAllowed("ns" + EC + "perm")
        String noCheckerEscapedFallthrough() {
            return "noCheckerEscapedFallthrough";
        }

        @PermissionsAllowed({ "scope:read", "scope" + EC + "admin" + EC + "read" })
        String mixedCheckerAndParsed(boolean scopeRead) {
            return "mixedCheckerAndParsed";
        }
    }

    @ApplicationScoped
    public static class PermissionCheckers {

        @PermissionChecker("org" + EC + "acme" + EC + "service")
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
