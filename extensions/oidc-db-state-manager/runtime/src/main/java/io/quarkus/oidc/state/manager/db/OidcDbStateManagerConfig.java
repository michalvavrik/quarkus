package io.quarkus.oidc.state.manager.db;

import io.quarkus.runtime.annotations.ConfigRoot;
import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;

import static io.quarkus.runtime.annotations.ConfigPhase.RUN_TIME;

@ConfigRoot(phase = RUN_TIME)
@ConfigMapping(prefix = "quarkus.oidc-db-state-manager")
public interface OidcDbStateManagerConfig {

    /**
     * Whether expired tokens should be deleted from database.
     * Tokens are deleted by every Quarkus instance and it might
     */
    @WithDefault("true")
    boolean deleteExpiredToken();

}
