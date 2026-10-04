package io.quarkus.spiffe.client.deployment;

import static io.quarkus.arc.processor.DotNames.APPLICATION_SCOPED;

import java.util.Collection;
import java.util.List;
import java.util.function.BooleanSupplier;
import java.util.function.Function;

import org.jboss.jandex.AnnotationInstance;
import org.jboss.jandex.IndexView;

import io.quarkus.arc.deployment.AdditionalBeanBuildItem;
import io.quarkus.deployment.Capabilities;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.annotations.ExecutionTime;
import io.quarkus.deployment.annotations.Record;
import io.quarkus.deployment.builditem.CombinedIndexBuildItem;
import io.quarkus.deployment.builditem.FeatureBuildItem;
import io.quarkus.spiffe.client.runtime.internal.SpiffeClientRecorder;
import io.quarkus.spiffe.svid.x509.X509Svid;
import io.quarkus.tls.deployment.spi.TlsCertificateBuildItem;

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

    @Record(ExecutionTime.STATIC_INIT)
    @BuildStep(onlyIf = SpiffeClientEnabled.class)
    List<TlsCertificateBuildItem> registerTlsConfigurations(CombinedIndexBuildItem combinedIndexBuildItem,
            Capabilities capabilities,
            SpiffeClientRecorder spiffeClientRecorder) {
        var index = combinedIndexBuildItem.getIndex();
        Collection<AnnotationInstance> x509SvidInstances = index.getAnnotationsWithRepeatable(X509Svid.class, index);

        if (x509SvidInstances.isEmpty()) {
            return List.of();
        }
        // FIXME: validate capability tls registry when we have it and there are instances

        // FIXME: migrate from recorder to that David's service when merged
        return x509SvidInstances.stream().map(createTlsCertificateBuildItem(spiffeClientRecorder, index)).toList();
    }

    private static Function<AnnotationInstance, TlsCertificateBuildItem> createTlsCertificateBuildItem(
            SpiffeClientRecorder recorder, IndexView index) {
        return annotationInstance -> {
            // TODO: validate that tls config does not exist in user configuration
            String tlsConfigurationName = annotationInstance.value("tls").asString();
            // TODO: validate spiffe id unique
            String spiffeId = annotationInstance.valueWithDefault(index, "spiffeId").asString();
            // TODO: validate reload period valid
            String reloadPeriod = annotationInstance.valueWithDefault(index, "reloadPeriod").asString();
            var configSupplier = recorder.createSpiffeTlsConfiguration(tlsConfigurationName, spiffeId, reloadPeriod);
            return new TlsCertificateBuildItem(tlsConfigurationName, configSupplier);
        };
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
