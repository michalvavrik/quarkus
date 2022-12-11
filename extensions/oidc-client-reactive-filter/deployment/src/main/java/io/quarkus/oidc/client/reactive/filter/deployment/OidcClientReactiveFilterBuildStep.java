package io.quarkus.oidc.client.reactive.filter.deployment;

import static io.quarkus.oidc.client.reactive.filter.runtime.TokensProducerRegistry.DEFAULT_TOKENS_PRODUCER;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import javax.inject.Singleton;

import org.jboss.jandex.AnnotationInstance;
import org.jboss.jandex.AnnotationValue;
import org.jboss.jandex.DotName;
import org.jboss.jandex.Type;

import io.quarkus.arc.deployment.AdditionalBeanBuildItem;
import io.quarkus.arc.deployment.SyntheticBeanBuildItem;
import io.quarkus.deployment.annotations.BuildProducer;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.annotations.BuildSteps;
import io.quarkus.deployment.annotations.ExecutionTime;
import io.quarkus.deployment.annotations.Record;
import io.quarkus.deployment.builditem.AdditionalIndexedClassesBuildItem;
import io.quarkus.deployment.builditem.CombinedIndexBuildItem;
import io.quarkus.deployment.builditem.nativeimage.ReflectiveClassBuildItem;
import io.quarkus.oidc.client.deployment.OidcClientBuildStep.IsEnabled;
import io.quarkus.oidc.client.deployment.OidcClientFilterClientNamesMapBuildItem;
import io.quarkus.oidc.client.filter.OidcClientFilter;
import io.quarkus.oidc.client.reactive.filter.OidcClientRequestReactiveFilter;
import io.quarkus.oidc.client.reactive.filter.runtime.OidcClientReactiveFilterConfig;
import io.quarkus.oidc.client.reactive.filter.runtime.OidcClientReactiveFilterRecorder;
import io.quarkus.oidc.client.reactive.filter.runtime.TokensProducer;
import io.quarkus.rest.client.reactive.deployment.DotNames;
import io.quarkus.rest.client.reactive.deployment.RegisterProviderAnnotationInstanceBuildItem;

@BuildSteps(onlyIf = IsEnabled.class)
public class OidcClientReactiveFilterBuildStep {

    private static final DotName OIDC_CLIENT_FILTER = DotName.createSimple(OidcClientFilter.class.getName());
    private static final DotName OIDC_CLIENT_REQUEST_REACTIVE_FILTER = DotName
            .createSimple(OidcClientRequestReactiveFilter.class.getName());

    // we simply pretend that @OidcClientFilter means @RegisterProvider(OidcClientRequestReactiveFilter.class)
    @BuildStep
    void oidcClientFilterSupport(CombinedIndexBuildItem indexBuildItem,
            BuildProducer<RegisterProviderAnnotationInstanceBuildItem> producer) {
        Collection<AnnotationInstance> instances = indexBuildItem.getIndex().getAnnotations(OIDC_CLIENT_FILTER);
        for (AnnotationInstance instance : instances) {
            String targetClass = instance.target().asClass().name().toString();
            producer.produce(new RegisterProviderAnnotationInstanceBuildItem(targetClass, AnnotationInstance.create(
                    DotNames.REGISTER_PROVIDER, instance.target(), List.of(AnnotationValue.createClassValue("value",
                            Type.create(OIDC_CLIENT_REQUEST_REACTIVE_FILTER, org.jboss.jandex.Type.Kind.CLASS))))));
        }
    }

    @BuildStep
    void registerProvider(BuildProducer<AdditionalBeanBuildItem> additionalBeans,
            BuildProducer<ReflectiveClassBuildItem> reflectiveClass,
            BuildProducer<AdditionalIndexedClassesBuildItem> additionalIndexedClassesBuildItem) {
        additionalBeans.produce(AdditionalBeanBuildItem.unremovableOf(OidcClientRequestReactiveFilter.class));
        additionalIndexedClassesBuildItem
                .produce(new AdditionalIndexedClassesBuildItem(OidcClientRequestReactiveFilter.class.getName()));
        reflectiveClass.produce(new ReflectiveClassBuildItem(true, true, OidcClientRequestReactiveFilter.class));
    }

    @BuildStep
    @Record(ExecutionTime.RUNTIME_INIT)
    List<SyntheticBeanBuildItem> createTokensProducers(Optional<OidcClientFilterClientNamesMapBuildItem> scanningResult,
            OidcClientReactiveFilterConfig config,
            OidcClientReactiveFilterRecorder recorder) {
        List<SyntheticBeanBuildItem> result = new ArrayList<>();
        final String configClientName = config.clientName.orElse(null);

        // register Tokens producer for each annotation instance like @OidcClientFilter(clientName = "myClientName")
        if (scanningResult.isPresent()) {
            boolean additionalProducerCreated = false;
            for (Map.Entry<String, String> invokerClassToClientName : scanningResult.get().getClientInvokerClassToName()
                    .entrySet()) {
                final String invokerClass = invokerClassToClientName.getKey();
                final String clientName = invokerClassToClientName.getValue();

                if (!clientName.equals(configClientName)) {
                    result.add(SyntheticBeanBuildItem
                            .configure(TokensProducer.class)
                            .unremovable()
                            .types(TokensProducer.class)
                            .supplier(recorder.createTokensProducer(clientName, invokerClass))
                            .scope(Singleton.class)
                            .unremovable()
                            .named(TokensProducer.class.getName() + "$$" + clientName)
                            .setRuntimeInit()
                            .done());
                    if (!additionalProducerCreated) {
                        additionalProducerCreated = true;
                    }
                }
            }
            if (additionalProducerCreated) {
                recorder.searchForNonDefaultProducers();
            }
        }

        // register default (primary) Tokens producer
        result.add(SyntheticBeanBuildItem
                .configure(TokensProducer.class)
                .unremovable()
                .types(TokensProducer.class)
                .supplier(recorder.createTokensProducer(configClientName, null))
                .scope(Singleton.class)
                .named(DEFAULT_TOKENS_PRODUCER)
                .unremovable()
                .setRuntimeInit()
                .done());

        return result;
    }
}
