package io.quarkus.security.runtime;

import java.util.Map;
import java.util.Set;

import io.quarkus.runtime.annotations.ConfigPhase;
import io.quarkus.runtime.annotations.ConfigRoot;
import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;

/**
 * Quarkus Security configuration.
 */
@ConfigMapping(prefix = "quarkus.security")
@ConfigRoot(phase = ConfigPhase.RUN_TIME)
public interface SecurityConfig {

    /**
     * Add roles granted to the `SecurityIdentity` based on the roles that the `SecurityIdentity` already have.
     * For example, the Quarkus OIDC extension can map roles from the verified JWT access token, and you may want
     * to remap them to a deployment specific roles.
     */
    Map<String, Set<String>> roles();

    /**
     * Security events configuration.
     */
    SecurityEventsConfig events();

    interface SecurityEventsConfig {

        /**
         * Whether security events should be fired.
         */
        @WithDefault("true")
        boolean enabled();

    }

}
