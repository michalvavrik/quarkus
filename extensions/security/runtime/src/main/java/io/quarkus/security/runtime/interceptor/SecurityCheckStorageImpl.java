package io.quarkus.security.runtime.interceptor;

import java.util.List;
import java.util.Map;

import io.quarkus.security.runtime.interceptor.check.SupplierRolesAllowedCheck;
import io.quarkus.security.spi.runtime.MethodDescription;
import io.quarkus.security.spi.runtime.SecurityCheck;
import io.quarkus.security.spi.runtime.SecurityCheckStorage;

public final class SecurityCheckStorageImpl implements SecurityCheckStorage {

    private final Map<MethodDescription, SecurityCheck> securityChecks;
    private final SecurityCheck defaultSecurityCheck;
    private final List<SupplierRolesAllowedCheck> configExpressionChecks;

    public SecurityCheckStorageImpl(Map<MethodDescription, SecurityCheck> securityChecks, SecurityCheck defaultSecurityCheck,
            List<? extends SupplierRolesAllowedCheck> configExpressionChecks) {
        this.securityChecks = Map.copyOf(securityChecks);
        this.defaultSecurityCheck = defaultSecurityCheck;
        this.configExpressionChecks = List.copyOf(configExpressionChecks);
    }

    @Override
    public SecurityCheck getSecurityCheck(MethodDescription methodDescription) {
        return securityChecks.get(methodDescription);
    }

    @Override
    public SecurityCheck getDefaultSecurityCheck() {
        return defaultSecurityCheck;
    }

    /**
     * Eagerly resolves the configuration expressions used in the {@code @RolesAllowed} annotations, so that
     * failures are reported when the application starts rather than when the first request is checked.
     * Must be called when the runtime configuration is available.
     */
    public void resolveRolesAllowedConfigExpressions() {
        for (SupplierRolesAllowedCheck check : configExpressionChecks) {
            check.resolveAllowedRoles();
        }
    }
}
