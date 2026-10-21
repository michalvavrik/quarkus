package io.quarkus.security.runtime.interceptor;

import java.util.List;
import java.util.Map;

import io.quarkus.security.runtime.interceptor.check.ConfigExpressionRolesAllowedCheck;
import io.quarkus.security.runtime.interceptor.check.ConfigExpressionRolesAllowedChecks;
import io.quarkus.security.spi.runtime.MethodDescription;
import io.quarkus.security.spi.runtime.SecurityCheck;
import io.quarkus.security.spi.runtime.SecurityCheckStorage;

public final class SecurityCheckStorageImpl implements SecurityCheckStorage {

    private final Map<MethodDescription, SecurityCheck> securityChecks;
    private final SecurityCheck defaultSecurityCheck;
    private final ConfigExpressionRolesAllowedChecks configExpressionChecks;

    public SecurityCheckStorageImpl(Map<MethodDescription, SecurityCheck> securityChecks, SecurityCheck defaultSecurityCheck,
            List<ConfigExpressionRolesAllowedCheck> configExpressionChecks) {
        this.securityChecks = Map.copyOf(securityChecks);
        this.defaultSecurityCheck = defaultSecurityCheck;
        this.configExpressionChecks = new ConfigExpressionRolesAllowedChecks(configExpressionChecks);
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
     * Returns the roles allowed checks whose roles contain configuration expressions.
     */
    public ConfigExpressionRolesAllowedChecks getConfigExpressionChecks() {
        return configExpressionChecks;
    }
}
