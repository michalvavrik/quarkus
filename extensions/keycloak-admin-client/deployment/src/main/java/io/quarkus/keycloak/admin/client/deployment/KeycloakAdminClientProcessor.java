package io.quarkus.keycloak.admin.client.deployment;

import static io.quarkus.keycloak.admin.client.common.KeycloakAdminClientFactory.ADMIN;

import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;

import javax.enterprise.context.RequestScoped;

import org.jboss.jandex.DotName;
import org.jboss.resteasy.client.jaxrs.internal.ResteasyClientBuilderImpl;
import org.jboss.resteasy.client.jaxrs.internal.proxy.ProxyBuilderImpl;
import org.keycloak.admin.client.JacksonProvider;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.json.StringListMapDeserializer;
import org.keycloak.json.StringOrArrayDeserializer;
import org.keycloak.json.StringOrArraySerializer;

import io.quarkus.arc.deployment.AdditionalBeanBuildItem;
import io.quarkus.arc.deployment.BeanArchiveIndexBuildItem;
import io.quarkus.arc.deployment.SyntheticBeanBuildItem;
import io.quarkus.arc.deployment.UnremovableBeanBuildItem;
import io.quarkus.builder.item.EmptyBuildItem;
import io.quarkus.deployment.annotations.BuildProducer;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.annotations.Consume;
import io.quarkus.deployment.annotations.ExecutionTime;
import io.quarkus.deployment.annotations.Produce;
import io.quarkus.deployment.annotations.Record;
import io.quarkus.deployment.builditem.AdditionalApplicationArchiveMarkerBuildItem;
import io.quarkus.deployment.builditem.nativeimage.ReflectiveClassBuildItem;
import io.quarkus.deployment.builditem.nativeimage.ReflectiveHierarchyIgnoreWarningBuildItem;
import io.quarkus.keycloak.admin.client.ResteasyKeycloakAdminClientRecorder;
import io.quarkus.keycloak.admin.client.common.AutoCloseableDestroyer;
import io.quarkus.keycloak.admin.client.common.KeycloakAdminClientBuildTimeConfig;
import io.quarkus.keycloak.admin.client.common.KeycloakAdminClientCommonProcessor;
import io.quarkus.keycloak.admin.client.common.UserConfiguredNamedAdminClients;
import io.quarkus.keycloak.admin.client.common.spi.deployment.AutoconfigureKeycloakAdminClientForDevServicesBuildItem;
import io.quarkus.keycloak.admin.client.common.spi.deployment.DefaultKeycloakAdminClientAuthZProviderBuildItem;
import io.quarkus.keycloak.admin.client.common.spi.deployment.KeycloakAuthorizationProvidersBuildItem;

public class KeycloakAdminClientProcessor {

    @BuildStep
    ReflectiveHierarchyIgnoreWarningBuildItem marker(BuildProducer<AdditionalApplicationArchiveMarkerBuildItem> prod) {
        prod.produce(new AdditionalApplicationArchiveMarkerBuildItem("org/keycloak/admin/client/"));
        prod.produce(new AdditionalApplicationArchiveMarkerBuildItem("org/keycloak/representations"));
        return new ReflectiveHierarchyIgnoreWarningBuildItem(new ReflectiveHierarchyIgnoreWarningBuildItem.DotNameExclusion(
                DotName.createSimple(MultivaluedHashMap.class.getName())));
    }

    @BuildStep
    ReflectiveClassBuildItem reflect() {
        return ReflectiveClassBuildItem.builder(ResteasyClientBuilderImpl.class, JacksonProvider.class, ProxyBuilderImpl.class,
                StringListMapDeserializer.class,
                StringOrArrayDeserializer.class,
                StringOrArraySerializer.class)
                .constructors(true)
                .methods(true)
                .build();
    }

    @BuildStep(onlyIf = UserConfiguredNamedAdminClients.class)
    public KeycloakAuthorizationProvidersBuildItem collectAuthZProviders(
            KeycloakAdminClientBuildTimeConfig buildTimeConfig,
            Optional<DefaultKeycloakAdminClientAuthZProviderBuildItem> defaultAuthZProviderBuildItem,
            BuildProducer<AdditionalBeanBuildItem> additionalBeanBuildItemBuildProducer,
            BuildProducer<UnremovableBeanBuildItem> unremovableBeans) {

        final var authZProvidersAnalysis = KeycloakAdminClientCommonProcessor
                .collectAuthZProviders(buildTimeConfig.namedAdminClients,
                        defaultAuthZProviderBuildItem
                                .map(DefaultKeycloakAdminClientAuthZProviderBuildItem::getDefaultAuthZProvider)
                                .orElse(null));

        if (authZProvidersAnalysis.defaultAuthZProviderClass != null) {
            additionalBeanBuildItemBuildProducer.produce(
                    AdditionalBeanBuildItem
                            .builder()
                            .setUnremovable()
                            .setDefaultScope(DotName.createSimple(RequestScoped.class.getName()))
                            .addBeanClass(authZProvidersAnalysis.defaultAuthZProviderClass)
                            .build());
        }

        if (!authZProvidersAnalysis.unremovableBeansClassNames.isEmpty()) {
            unremovableBeans
                    .produce(UnremovableBeanBuildItem.beanClassNames(authZProvidersAnalysis.unremovableBeansClassNames));
        }

        return new KeycloakAuthorizationProvidersBuildItem(authZProvidersAnalysis.clientNameToAuthZProviderClassName);
    }

    @Produce(EmptyBuildItem.class)
    @BuildStep(onlyIf = UserConfiguredNamedAdminClients.class)
    public void validateAuthZProviders(BeanArchiveIndexBuildItem beanArchiveIndexBuildItem,
            KeycloakAuthorizationProvidersBuildItem keycloakAuthorizationProvidersBuildItem) {
        KeycloakAdminClientCommonProcessor.validateAuthZProviders(
                keycloakAuthorizationProvidersBuildItem.getClientNameToAuthZProviderClassName(),
                beanArchiveIndexBuildItem.getIndex());
    }

    @Consume(EmptyBuildItem.class)
    @BuildStep(onlyIf = UserConfiguredNamedAdminClients.class)
    @Record(ExecutionTime.RUNTIME_INIT)
    public void registerKeycloakAdminClientBeans(ResteasyKeycloakAdminClientRecorder recorder,
            KeycloakAdminClientBuildTimeConfig keycloakAdminClientBuildTimeConfig,
            KeycloakAuthorizationProvidersBuildItem authZProviders,
            BuildProducer<SyntheticBeanBuildItem> syntheticBeanBuildItemBuildProducer) {

        // Register Keycloak admin client bean for each client with configuration
        for (var nameToClientConfig : keycloakAdminClientBuildTimeConfig.namedAdminClients.entrySet()) {
            final String clientName = nameToClientConfig.getKey();
            produceAdminClientBean(
                    recorder.createAdminClientBean(clientName, nameToClientConfig.getValue().authMethod,
                            authZProviders.getClientNameToAuthZProviderClassName().get(clientName)),
                    clientName, syntheticBeanBuildItemBuildProducer);
        }
    }

    @BuildStep(onlyIfNot = UserConfiguredNamedAdminClients.class)
    @Record(ExecutionTime.RUNTIME_INIT)
    public void autoconfigureAdminClientForKeycloakDevServices(ResteasyKeycloakAdminClientRecorder recorder,
            KeycloakAdminClientBuildTimeConfig keycloakAdminClientBuildTimeConfig,
            List<AutoconfigureKeycloakAdminClientForDevServicesBuildItem> autoconfigureForKeycloakDevServices,
            BuildProducer<SyntheticBeanBuildItem> syntheticBeanBuildItemBuildProducer) {

        if (!autoconfigureForKeycloakDevServices.isEmpty()
                && keycloakAdminClientBuildTimeConfig.devServicesEnabled) {

            // User configured no clients, but the Keycloak Dev Services are running and autoconfiguration is enabled
            produceAdminClientBean(recorder.createDefaultDevServicesBean(), ADMIN, syntheticBeanBuildItemBuildProducer);
        }
    }

    private void produceAdminClientBean(Supplier<Keycloak> keycloakSupplier, String clientName,
            BuildProducer<SyntheticBeanBuildItem> syntheticBeanBuildItemBuildProducer) {
        syntheticBeanBuildItemBuildProducer.produce(SyntheticBeanBuildItem
                .configure(Keycloak.class)
                // use @RequestScoped as we don't want to keep client connection open too long
                .scope(RequestScoped.class)
                .setRuntimeInit()
                .named(clientName)
                .unremovable()
                .supplier(keycloakSupplier)
                .destroyer(AutoCloseableDestroyer.class)
                .done());
    }

}
