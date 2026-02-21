package io.quarkus.email.authentication.deployment;

import static io.quarkus.arc.deployment.AdditionalBeanBuildItem.builder;
import static io.quarkus.arc.processor.DotNames.SINGLETON;
import static io.quarkus.email.authentication.runtime.internal.EmailAuthenticationRecorder.LIVE_RELOAD_ENCRYPTION_KEY;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.function.BooleanSupplier;

import io.quarkus.arc.deployment.AdditionalBeanBuildItem;
import io.quarkus.deployment.Feature;
import io.quarkus.deployment.IsDevServicesSupportedByLaunchMode;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.annotations.BuildSteps;
import io.quarkus.deployment.annotations.ExecutionTime;
import io.quarkus.deployment.annotations.Produce;
import io.quarkus.deployment.annotations.Record;
import io.quarkus.deployment.builditem.DevServicesResultBuildItem;
import io.quarkus.deployment.builditem.ServiceStartBuildItem;
import io.quarkus.deployment.builditem.Startable;
import io.quarkus.deployment.dev.devservices.DevServicesConfig;
import io.quarkus.email.authentication.runtime.internal.EmailAuthenticationRecorder;
import io.quarkus.vertx.http.deployment.VertxWebRouterBuildItem;
import io.quarkus.vertx.http.runtime.VertxHttpBuildTimeConfig;

@BuildSteps(onlyIf = EmailAuthenticationProcessor.IsEmailAuthenticationEnabled.class)
class EmailAuthenticationProcessor {

    private static final String MECHANISM_NAME = "io.quarkus.email.authentication.runtime.internal.EmailAuthenticationMechanism";
    private static final String DEFAULT_STORAGE_NAME = "io.quarkus.email.authentication.runtime.internal.CookieEmailAuthenticationTokenStorage";
    private static final String DEFAULT_SENDER_NAME = "io.quarkus.email.authentication.runtime.internal.DefaultEmailAuthenticationTokenSender";

    @BuildStep
    List<AdditionalBeanBuildItem> registerCdiBeans() {
        return List.of(
                AdditionalBeanBuildItem.builder()
                        .addBeanClasses(DEFAULT_SENDER_NAME, DEFAULT_STORAGE_NAME)
                        .setDefaultScope(SINGLETON)
                        .build(),
                AdditionalBeanBuildItem.builder()
                        .addBeanClasses(MECHANISM_NAME)
                        .setDefaultScope(SINGLETON)
                        .setUnremovable()
                        .build());
    }

    @Produce(ServiceStartBuildItem.class)
    @BuildStep(onlyIf = IsEagerAuthenticationDisabled.class)
    @Record(ExecutionTime.RUNTIME_INIT)
    void registerLazyAuthRouteHandler(EmailAuthenticationRecorder recorder, VertxWebRouterBuildItem vertxWebRouter) {
        recorder.registerEmailAuthRouteHandler(vertxWebRouter.getHttpRouter());
    }

    @BuildStep(onlyIf = { IsDevServicesSupportedByLaunchMode.class, DevServicesConfig.Enabled.class })
    DevServicesResultBuildItem useSameEncryptionKeyAfterRestart() {
        // Quarkus should recognize that the service config didn't change (as it is a constant),
        // thus generate our encryption key only once and keep it among live reloads
        return DevServicesResultBuildItem.owned()
                .feature(Feature.SECURITY)
                .serviceConfig(1)
                .configProvider(Map.of(
                        LIVE_RELOAD_ENCRYPTION_KEY, s -> EmailAuthenticationRecorder.generateEncryptionKey()))
                .postStartHook(s -> {
                    // keep this dev service silent
                })
                .startable(() -> new Startable() {
                    @Override
                    public void start() {

                    }

                    @Override
                    public String getConnectionInfo() {
                        return "";
                    }

                    @Override
                    public String getContainerId() {
                        return "";
                    }

                    @Override
                    public void close() throws IOException {

                    }
                })
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
