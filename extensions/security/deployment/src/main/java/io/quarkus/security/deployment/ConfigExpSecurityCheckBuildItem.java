package io.quarkus.security.deployment;

import java.util.List;

import io.quarkus.builder.item.SimpleBuildItem;

/**
 * Security checks created for annotations like {@link javax.annotation.security.RolesAllowed} and
 * {@link io.quarkus.security.PermissionsAllowed} may contain config expressions. These expressions need to be resolved
 * at runtime, while security checks are created at build time. Config expression resolvers should be registered against
 * this build time in order to get resolved at runtime.
 */
public final class ConfigExpSecurityCheckBuildItem extends SimpleBuildItem {

    final List<Runnable> securityChecksWithConfigExpResolvers;

    ConfigExpSecurityCheckBuildItem(List<Runnable> securityChecksWithConfigExpResolvers) {
        this.securityChecksWithConfigExpResolvers = List.copyOf(securityChecksWithConfigExpResolvers);
    }
}
