package io.quarkus.security.spi.runtime;

import java.util.Map;

/**
 * Security checks contributed by an extension for the methods it secures.
 * <p>
 * Register the contribution as a static-init service of this type named after the contributing extension. The
 * Quarkus Security extension applies the checks to the methods when it creates the {@link SecurityCheckStorage}.
 * A contributed check replaces the check created from the standard security annotations of the method, and a
 * method must not be contributed by more than one extension.
 */
public final class SecurityCheckContribution {

    private final Map<MethodDescription, SecurityCheck> securityChecks;

    public SecurityCheckContribution(Map<MethodDescription, SecurityCheck> securityChecks) {
        this.securityChecks = Map.copyOf(securityChecks);
    }

    /**
     * @return the contributed security checks keyed by the method they secure
     */
    public Map<MethodDescription, SecurityCheck> securityChecks() {
        return securityChecks;
    }
}
