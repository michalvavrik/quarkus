package io.quarkus.oidc.state.manager.db.deployment;

import io.quarkus.runtime.annotations.ConfigRoot;
import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;

@ConfigRoot
@ConfigMapping(prefix = "quarkus.oidc-db-state-manager")
public interface OidcDbStateManagerBuildTimeConfig {

    /**
     * If the OIDC Database State Manager extension is enabled.
     */
    @WithDefault("${quarkus.oidc.enabled:true}")
    boolean enabled();

}
