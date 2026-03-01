package io.quarkus.oidc.spiffe.deployment;

import io.quarkus.runtime.annotations.ConfigRoot;
import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;

/**
 * OIDC SPIFFE build time configuration.
 */
@ConfigMapping(prefix = "quarkus.oidc-spiffe")
@ConfigRoot
interface OidcSpiffeBuildTimeConfig {

    /**
     * Whether the OIDC SPIFFE extension is enabled.
     */
    @WithDefault("true")
    boolean enabled();
}
