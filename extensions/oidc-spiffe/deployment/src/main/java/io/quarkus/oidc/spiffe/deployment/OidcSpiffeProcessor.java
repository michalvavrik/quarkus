package io.quarkus.oidc.spiffe.deployment;

import static io.quarkus.arc.processor.DotNames.SINGLETON;

import java.util.function.BooleanSupplier;

import io.quarkus.arc.deployment.AdditionalBeanBuildItem;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.annotations.BuildSteps;
import io.quarkus.deployment.builditem.FeatureBuildItem;

@BuildSteps(onlyIf = OidcSpiffeProcessor.IsEnabled.class)
class OidcSpiffeProcessor {

    private static final String FEATURE = "oidc-spiffe";
    private static final String SPIFFE_CLIENT_BUILDER_IMPL = "io.quarkus.oidc.spiffe.runtime.internal.OidcSpiffeClientBuilderImpl";

    @BuildStep
    FeatureBuildItem feature() {
        return new FeatureBuildItem(FEATURE);
    }

    @BuildStep
    AdditionalBeanBuildItem registerSpiffeClientBuilder() {
        return AdditionalBeanBuildItem.builder()
                .addBeanClasses(SPIFFE_CLIENT_BUILDER_IMPL)
                .setDefaultScope(SINGLETON)
                .setUnremovable()
                .build();
    }

    static final class IsEnabled implements BooleanSupplier {

        private final boolean enabled;

        IsEnabled(OidcSpiffeBuildTimeConfig config) {
            this.enabled = config.enabled();
        }

        @Override
        public boolean getAsBoolean() {
            return enabled;
        }
    }
}
