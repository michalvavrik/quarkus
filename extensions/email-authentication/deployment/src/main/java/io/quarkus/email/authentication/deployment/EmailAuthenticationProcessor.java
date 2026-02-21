package io.quarkus.email.authentication.deployment;

import java.util.function.BooleanSupplier;

import io.quarkus.arc.deployment.AdditionalBeanBuildItem;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.annotations.BuildSteps;

@BuildSteps(onlyIf = EmailAuthenticationProcessor.IsEmailAuthenticationEnabled.class)
class EmailAuthenticationProcessor {

    private static final String MECHANISM_NAME = "io.quarkus.email.authentication.runtime.internal.EmailAuthenticationMechanism";
    private static final String DEFAULT_STORAGE_NAME = "";
    private static final String DEFAULT_SENDER_NAME = "";

    @BuildStep
    AdditionalBeanBuildItem registerCdiBeans() {
        return AdditionalBeanBuildItem.builder().addBeanClasses(MECHANISM_NAME, DEFAULT_SENDER_NAME, DEFAULT_STORAGE_NAME)
                .build();
    }

    static final class IsEmailAuthenticationEnabled implements BooleanSupplier {

        private final boolean enabled;

        IsEmailAuthenticationEnabled(EmailAuthenticationBuildTimeConfig buildTimeConfig) {
            this.enabled = buildTimeConfig.enabled();
        }

        @Override
        public boolean getAsBoolean() {
            return enabled;
        }
    }
}
