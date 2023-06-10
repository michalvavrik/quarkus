package io.quarkus.oidc.state.manager.db.deployment;

import java.util.function.BooleanSupplier;

import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.annotations.BuildSteps;

@BuildSteps(onlyIf = OidcDbStateManagerProcessor.IsEnabled.class)
public class OidcDbStateManagerProcessor {

    @BuildStep
    void createDbStateManager() {

    }

    public static class IsEnabled implements BooleanSupplier {
        OidcDbStateManagerBuildTimeConfig config;

        public boolean getAsBoolean() {
            return config.enabled();
        }
    }
}
