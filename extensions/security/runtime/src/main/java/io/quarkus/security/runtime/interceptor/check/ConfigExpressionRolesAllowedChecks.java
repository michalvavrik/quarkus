package io.quarkus.security.runtime.interceptor.check;

import java.util.List;

/**
 * Roles allowed checks whose roles contain configuration expressions.
 *
 * @param checks the checks, resolved eagerly when the application starts
 */
public record ConfigExpressionRolesAllowedChecks(List<ConfigExpressionRolesAllowedCheck> checks) {

    public ConfigExpressionRolesAllowedChecks {
        checks = List.copyOf(checks);
    }

    /**
     * Eagerly resolves the configuration expressions used in the {@code @RolesAllowed} annotations, so that
     * failures are reported when the application starts rather than when the first request is checked.
     * Must be called when the runtime configuration is available.
     */
    public void resolve() {
        for (ConfigExpressionRolesAllowedCheck check : checks) {
            check.resolveAllowedRoles();
        }
    }
}
