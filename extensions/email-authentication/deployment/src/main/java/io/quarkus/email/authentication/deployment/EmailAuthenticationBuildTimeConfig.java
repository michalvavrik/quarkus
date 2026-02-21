package io.quarkus.email.authentication.deployment;

import io.quarkus.runtime.annotations.ConfigRoot;
import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;

/**
 * Email authentication configuration.
 */
@ConfigMapping(prefix = "quarkus.email-authentication")
@ConfigRoot
interface EmailAuthenticationBuildTimeConfig {

    /**
     * If the email authentication is enabled.
     */
    @WithDefault("true")
    boolean enabled();

}
