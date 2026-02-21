package io.quarkus.email.authentication.deployment;

import static io.quarkus.arc.deployment.AdditionalBeanBuildItem.builder;

import java.util.function.BooleanSupplier;

import io.quarkus.arc.deployment.AdditionalBeanBuildItem;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.annotations.BuildSteps;
import io.quarkus.deployment.annotations.ExecutionTime;
import io.quarkus.deployment.annotations.Produce;
import io.quarkus.deployment.annotations.Record;
import io.quarkus.deployment.builditem.ServiceStartBuildItem;
import io.quarkus.email.authentication.runtime.internal.EmailAuthenticationRecorder;
import io.quarkus.vertx.http.deployment.VertxWebRouterBuildItem;
import io.quarkus.vertx.http.runtime.VertxHttpBuildTimeConfig;

@BuildSteps(onlyIf = EmailAuthenticationProcessor.IsEmailAuthenticationEnabled.class)
class EmailAuthenticationProcessor {

    private static final String MECHANISM_NAME = "io.quarkus.email.authentication.runtime.internal.EmailAuthenticationMechanism";
    private static final String DEFAULT_STORAGE_NAME = "io.quarkus.email.authentication.runtime.internal.CookieEmailAuthenticationTokenStorage";
    private static final String DEFAULT_SENDER_NAME = "io.quarkus.email.authentication.runtime.internal.DefaultEmailAuthenticationTokenSender";

    @BuildStep
    AdditionalBeanBuildItem registerCdiBeans() {
        return builder().addBeanClasses(MECHANISM_NAME, DEFAULT_SENDER_NAME, DEFAULT_STORAGE_NAME).build();
    }

    @Produce(ServiceStartBuildItem.class)
    @BuildStep(onlyIf = IsEagerAuthenticationDisabled.class)
    @Record(ExecutionTime.RUNTIME_INIT)
    void registerLazyAuthRouteHandler(EmailAuthenticationRecorder recorder, VertxWebRouterBuildItem vertxWebRouter) {
        recorder.registerEmailAuthRouteHandler(vertxWebRouter.getHttpRouter());
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

    static final class IsEagerAuthenticationDisabled implements BooleanSupplier {

        private final boolean disabled;

        IsEagerAuthenticationDisabled(VertxHttpBuildTimeConfig buildTimeConfig) {
            this.disabled = !buildTimeConfig.auth().proactive();
        }

        @Override
        public boolean getAsBoolean() {
            return disabled;
        }
    }
}
