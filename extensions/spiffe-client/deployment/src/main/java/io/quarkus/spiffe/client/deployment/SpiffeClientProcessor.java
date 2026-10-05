package io.quarkus.spiffe.client.deployment;

import static io.quarkus.arc.processor.DotNames.APPLICATION_SCOPED;
import static io.quarkus.runtime.configuration.DurationConverter.parseDuration;

import java.time.Duration;
import java.util.Collection;
import java.util.List;
import java.util.function.BooleanSupplier;

import org.jboss.jandex.AnnotationInstance;
import org.jboss.jandex.IndexView;

import io.quarkus.arc.deployment.AdditionalBeanBuildItem;
import io.quarkus.core.Phase;
import io.quarkus.core.deployment.service.ServiceRegistrar;
import io.quarkus.deployment.Capabilities;
import io.quarkus.deployment.Capability;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.builditem.CombinedIndexBuildItem;
import io.quarkus.deployment.builditem.FeatureBuildItem;
import io.quarkus.spiffe.client.runtime.internal.SpiffeTlsConfiguration;
import io.quarkus.spiffe.client.runtime.internal.SpiffeTlsConfiguration.X509SvidAnnotationDetails;
import io.quarkus.spiffe.svid.x509.X509Svid;
import io.quarkus.tls.TlsConfigurationRegistry;

final class SpiffeClientProcessor {

    private static final String CLIENT_IMPL_CLASS = "io.quarkus.spiffe.client.runtime.internal.SpiffeClientImpl";
    static final String FEATURE = "spiffe-client";

    @BuildStep
    FeatureBuildItem feature() {
        return new FeatureBuildItem(FEATURE);
    }

    @BuildStep(onlyIf = SpiffeClientEnabled.class)
    AdditionalBeanBuildItem registerClientAsCdiBean() {
        return AdditionalBeanBuildItem.builder()
                .addBeanClass(CLIENT_IMPL_CLASS)
                .setDefaultScope(APPLICATION_SCOPED)
                .setUnremovable()
                .build();
    }

    @BuildStep(onlyIf = SpiffeClientEnabled.class)
    void registerTlsConfigurations(CombinedIndexBuildItem combinedIndexBuildItem,
            ServiceRegistrar serviceRegistrar, Capabilities capabilities) {
        final IndexView index = combinedIndexBuildItem.getIndex();
        final Collection<AnnotationInstance> x509SvidInstances = index.getAnnotationsWithRepeatable(X509Svid.class, index);

        if (!x509SvidInstances.isEmpty()) {
            if (capabilities.isMissing(Capability.TLS_REGISTRY)) {
                throw new RuntimeException(X509Svid.class.getName() + " annotation cannot be used without TLS registry");
            }
            List<X509SvidAnnotationDetails> detailsList = List.copyOf(x509SvidInstances.stream()
                    .map(annotationInstance -> {
                        // FIXME: validate not created this tls config already and that the same spiffe id not used yet
                        String tlsConfigurationName = annotationInstance.value("tls").asString();
                        // TODO: validate spiffe id unique
                        String spiffeId = annotationInstance.valueWithDefault(index, "spiffeId").asString();
                        String reloadPeriodAsString = annotationInstance.valueWithDefault(index, "reloadPeriod").asString();
                        Duration reloadPeriod = parseDuration(reloadPeriodAsString);
                        return new X509SvidAnnotationDetails(tlsConfigurationName, spiffeId, reloadPeriod);
                    })
                    .toList());
            serviceRegistrar
                    .forService("io.quarkus.spiffe.client.register.tls.configurations")
                    .atPhase(Phase.INFRASTRUCTURE)
                    .require(TlsConfigurationRegistry.class)
                    .onStart((ctx, tlsConfigurationRegistry) -> detailsList.stream()
                            .map(SpiffeTlsConfiguration::new)
                            .forEach(tlsConfiguration -> {
                                tlsConfigurationRegistry.register(tlsConfiguration.getName(), tlsConfiguration);
                                ctx.onStop(tlsConfiguration::close);
                            }));
            serviceRegistrar
                    .forService("io.quarkus.spiffe.client.initialize.tls.configurations")
                    .atPhase(Phase.DATA)
                    .require(TlsConfigurationRegistry.class)
                    .onStartAsync((ctx, tlsConfigurationRegistry) -> detailsList.stream()
                            .map(X509SvidAnnotationDetails::tlsConfigurationName)
                            .forEach(tlsConfigurationName -> {
                                if (tlsConfigurationRegistry.get(tlsConfigurationName)
                                        .orElse(null) instanceof SpiffeTlsConfiguration spiffeTlsConfiguration) {
                                    // TODO: possibly we shouldn't be initializing and stopping tls configurations
                                    //      it should really be one workload, hence it should live separately
                                    //      and only be consumed by all the tls configurations instead of X clients!
                                    // TODO: log when we need to block inside such a service
                                    spiffeTlsConfiguration.initialize(ctx::startComplete, ctx::startFailed);
                                }
                            }));
        }
    }

    static final class SpiffeClientEnabled implements BooleanSupplier {

        private final boolean enabled;

        SpiffeClientEnabled(SpiffeClientBuildTimeConfig config) {
            this.enabled = config.enabled();
        }

        @Override
        public boolean getAsBoolean() {
            return enabled;
        }
    }
}
