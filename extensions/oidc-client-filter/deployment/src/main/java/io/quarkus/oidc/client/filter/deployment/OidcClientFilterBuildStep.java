package io.quarkus.oidc.client.filter.deployment;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import javax.inject.Singleton;

import org.jboss.jandex.DotName;

import io.quarkus.arc.deployment.AdditionalBeanBuildItem;
import io.quarkus.arc.deployment.SyntheticBeanBuildItem;
import io.quarkus.deployment.annotations.BuildProducer;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.annotations.BuildSteps;
import io.quarkus.deployment.annotations.ExecutionTime;
import io.quarkus.deployment.annotations.Record;
import io.quarkus.deployment.builditem.nativeimage.ReflectiveClassBuildItem;
import io.quarkus.oidc.client.deployment.OidcClientBuildStep.IsEnabled;
import io.quarkus.oidc.client.deployment.OidcClientFilterClientNamesMapBuildItem;
import io.quarkus.oidc.client.filter.OidcClientFilter;
import io.quarkus.oidc.client.filter.OidcClientRequestFilter;
import io.quarkus.oidc.client.filter.runtime.OidcClientFilterConfig;
import io.quarkus.oidc.client.filter.runtime.OidcClientFilterRecorder;
import io.quarkus.oidc.client.runtime.AbstractTokensProducer;
import io.quarkus.restclient.deployment.RestClientAnnotationProviderBuildItem;
import io.quarkus.resteasy.common.spi.ResteasyJaxrsProviderBuildItem;

@BuildSteps(onlyIf = IsEnabled.class)
public class OidcClientFilterBuildStep {

    private static final DotName OIDC_CLIENT_FILTER = DotName.createSimple(OidcClientFilter.class.getName());

    OidcClientFilterConfig config;

    @BuildStep
    void registerProvider(BuildProducer<AdditionalBeanBuildItem> additionalBeans,
            BuildProducer<ReflectiveClassBuildItem> reflectiveClass,
            BuildProducer<ResteasyJaxrsProviderBuildItem> jaxrsProviders,
            BuildProducer<RestClientAnnotationProviderBuildItem> restAnnotationProvider) {
        additionalBeans.produce(AdditionalBeanBuildItem.unremovableOf(OidcClientRequestFilter.class));
        reflectiveClass.produce(new ReflectiveClassBuildItem(true, true, OidcClientRequestFilter.class));
        if (config.registerFilter) {
            jaxrsProviders.produce(new ResteasyJaxrsProviderBuildItem(OidcClientRequestFilter.class.getName()));
        } else {
            restAnnotationProvider.produce(new RestClientAnnotationProviderBuildItem(OIDC_CLIENT_FILTER,
                    OidcClientRequestFilter.class));
        }
    }

    @Record(ExecutionTime.STATIC_INIT)
    @BuildStep
    void setClientInvokerToName(OidcClientFilterRecorder recorder,
            Optional<OidcClientFilterClientNamesMapBuildItem> clientNamesMap) {
        if (clientNamesMap.isPresent()) {
            // we collected all client names specified via @OidcClientFilter("clientId")
            // and annotated classes as map;
            // now we record the map so that OidcClientRequestFilter can match each request with OidcClient
            if (config.clientName.isPresent()) {
                // don't create TokensProducer for OidcClient configured via property as there is no advantage
                // OidcClientRequestFilter will use configured OidcClient by default
                final String configClientName = config.clientName.get();
                final Map<String, String> invokerClassToClientName = new HashMap<>();
                for (Map.Entry<String, String> entry : clientNamesMap.get().getClientInvokerClassToName().entrySet()) {
                    final String clientName = entry.getValue();
                    // by ignoring config name we ensure missing bean is not looked up
                    if (!configClientName.equals(clientName)) {
                        invokerClassToClientName.put(entry.getKey(), clientName);
                    }
                }
                if (!invokerClassToClientName.isEmpty()) {
                    recorder.setClientInvokerToName(invokerClassToClientName);
                }
            } else {
                recorder.setClientInvokerToName(clientNamesMap.get().getClientInvokerClassToName());
            }
        }
    }

    @Record(ExecutionTime.RUNTIME_INIT)
    @BuildStep
    void createTokensProducerForNonDefaultOidcClients(OidcClientFilterRecorder recorder,
            Optional<OidcClientFilterClientNamesMapBuildItem> scanningResult,
            BuildProducer<SyntheticBeanBuildItem> beanProducer) {
        if (scanningResult.isPresent()) {
            // register Tokens producer for each annotation instance like @OidcClientFilter(clientName = "myClientName")
            for (String clientName : scanningResult.get().getClientInvokerClassToName().values()) {
                if (!clientName.equals(config.clientName.orElse(null))) {
                    beanProducer.produce(SyntheticBeanBuildItem
                            .configure(AbstractTokensProducer.class)
                            .unremovable()
                            .types(AbstractTokensProducer.class)
                            .supplier(recorder.createTokensProducer(clientName))
                            .scope(Singleton.class)
                            .unremovable()
                            .named(OidcClientFilterRecorder.toTokensProducerBeanName(clientName))
                            .setRuntimeInit()
                            .done());
                }
            }
        }
    }
}
