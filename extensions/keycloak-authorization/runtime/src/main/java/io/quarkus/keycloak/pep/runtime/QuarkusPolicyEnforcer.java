package io.quarkus.keycloak.pep.runtime;

import static org.keycloak.representations.adapters.config.PolicyEnforcerConfig.EnforcementMode.DISABLED;

import java.util.Collection;

import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.authorization.PathCache;
import org.keycloak.adapters.authorization.PolicyEnforcer;
import org.keycloak.common.util.PathMatcher;
import org.keycloak.representations.adapters.config.AdapterConfig;
import org.keycloak.representations.adapters.config.PolicyEnforcerConfig;

public class QuarkusPolicyEnforcer extends PolicyEnforcer {

    private final boolean hasHandledDisabledPaths;
    private final OfflinePathMatcher offlinePathMatcher;

    public QuarkusPolicyEnforcer(KeycloakDeployment deployment, AdapterConfig adapterConfig) {
        super(deployment, adapterConfig);

        // we want to prevent unnecessary remote call when getting path config
        // that is only possible when enforcement is disabled for the path and there is no pattern
        // as pattern call to Keycloak
        if (!getEnforcerConfig().getLazyLoadPaths()) {
            boolean anyPathHasPattern = false;
            boolean anyPathEndsWithWildcard = false;
            for (PolicyEnforcerConfig.PathConfig pathConfig : getPaths().values()) {
                if (pathConfig.getEnforcementMode() == DISABLED && pathConfig.getPath() != null) {
                    if (pathConfig.hasPattern()) {
                        anyPathHasPattern = true;
                        break;
                    }

                    // we only care about paths that ends with a wildcard as static paths does not require
                    // remote calls anyway
                    if (getPathMatcher().endsWithWildcard(pathConfig.getPath())) {
                        anyPathEndsWithWildcard = true;
                    }
                }
            }

            this.hasHandledDisabledPaths = anyPathEndsWithWildcard && !anyPathHasPattern;
        } else {
            this.hasHandledDisabledPaths = false;
        }

        if (this.hasHandledDisabledPaths) {
            this.offlinePathMatcher = new OfflinePathMatcher(this);
        } else {
            this.offlinePathMatcher = null;
        }
    }

    /**
     * Offline path check that determines whether enforcement is disabled.
     * It's safe to rely on 'true' values (=disabled enforcement), however 'false' values
     * may mean that enforcement strategy wasn't resolved.
     *
     * @param targetUri target URI
     * @return true if we can't reliably determine that enforcement is disabled for the path
     */
    boolean isPathEnforcementDisabled(String targetUri) {
        if (hasHandledDisabledPaths) {
            var pathConfig = offlinePathMatcher.matches(targetUri);
            return pathConfig != null && !pathConfig.hasPattern() && pathConfig.getEnforcementMode() == DISABLED;
        }
        return false;
    }

    private static final class OfflinePathMatcher extends PathMatcher<PolicyEnforcerConfig.PathConfig> {

        private final PathCache pathCache;
        private final Collection<PolicyEnforcerConfig.PathConfig> paths;

        public OfflinePathMatcher(PolicyEnforcer policyEnforcer) {
            PolicyEnforcerConfig.PathCacheConfig cacheConfig = policyEnforcer.getEnforcerConfig().getPathCacheConfig();
            if (cacheConfig == null) {
                cacheConfig = new PolicyEnforcerConfig.PathCacheConfig();
            }
            this.pathCache = new PathCache(cacheConfig.getMaxEntries(), cacheConfig.getLifespan(), policyEnforcer.getPaths());
            this.paths = policyEnforcer.getPaths().values();
        }

        @Override
        protected String getPath(PolicyEnforcerConfig.PathConfig pathConfig) {
            return pathConfig.getPath();
        }

        @Override
        protected Collection<PolicyEnforcerConfig.PathConfig> getPaths() {
            return paths;
        }

        @Override
        public PolicyEnforcerConfig.PathConfig matches(String targetUri) {
            PolicyEnforcerConfig.PathConfig pathConfig = pathCache.get(targetUri);

            if (pathCache.containsKey(targetUri) || pathConfig != null) {
                return pathConfig;
            }

            pathConfig = super.matches(targetUri);
            pathCache.put(targetUri, pathConfig);
            return pathConfig;
        }
    }
}
