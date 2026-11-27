package io.quarkus.spiffe.client.deployment;

import static io.quarkus.arc.processor.DotNames.APPLICATION_SCOPED;
import static io.quarkus.spiffe.svid.x509.X509Svid.SAME_TRUST_DOMAIN;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.BooleanSupplier;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import org.jboss.jandex.AnnotationInstance;
import org.jboss.jandex.IndexView;

import io.quarkus.arc.deployment.AdditionalBeanBuildItem;
import io.quarkus.arc.deployment.GeneratedBeanBuildItem;
import io.quarkus.arc.deployment.GeneratedBeanGizmo2Adaptor;
import io.quarkus.arc.deployment.SyntheticBeansRuntimeInitBuildItem;
import io.quarkus.arc.runtime.BeanContainer;
import io.quarkus.builder.item.MultiBuildItem;
import io.quarkus.core.Phase;
import io.quarkus.core.deployment.service.ServiceRegistrar;
import io.quarkus.deployment.Capabilities;
import io.quarkus.deployment.Capability;
import io.quarkus.deployment.annotations.BuildProducer;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.builditem.AdditionalIndexedClassesBuildItem;
import io.quarkus.deployment.builditem.CombinedIndexBuildItem;
import io.quarkus.deployment.builditem.FeatureBuildItem;
import io.quarkus.deployment.builditem.ServiceStartBuildItem;
import io.quarkus.deployment.builditem.nativeimage.ConstantBootstrapBuildItem;
import io.quarkus.gizmo2.Const;
import io.quarkus.gizmo2.Gizmo;
import io.quarkus.gizmo2.ParamVar;
import io.quarkus.gizmo2.desc.ConstructorDesc;
import io.quarkus.runtime.configuration.ConfigurationException;
import io.quarkus.spiffe.client.SpiffeConnectionException;
import io.quarkus.spiffe.client.runtime.internal.SpiffeClientConfig;
import io.quarkus.spiffe.client.runtime.internal.SpiffeValidator;
import io.quarkus.spiffe.client.runtime.internal.tls.SpiffeTlsStoreProvider;
import io.quarkus.spiffe.svid.x509.X509Svid;
import io.quarkus.spiffe.svid.x509.X509SvidClient;
import io.quarkus.tls.TlsConfigurationRegistry;
import io.smallrye.common.annotation.Identifier;
import io.vertx.core.Vertx;

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
    AdditionalIndexedClassesBuildItem indexX509SvidAnnotation() {
        // the annotation lives in the runtime API module, which is not indexed; Jandex needs the annotation definition
        // to resolve the @Repeatable container when the @X509Svid instances are collected from the combined index
        return new AdditionalIndexedClassesBuildItem(X509Svid.class.getName(), X509Svid.List.class.getName());
    }

    @BuildStep(onlyIf = SpiffeClientEnabled.class)
    List<X509SvidDeclarationBuildItem> collectX509SvidDeclarations(CombinedIndexBuildItem combinedIndexBuildItem,
            Capabilities capabilities) {
        IndexView index = combinedIndexBuildItem.getIndex();
        Collection<AnnotationInstance> x509SvidInstances = index.getAnnotationsWithRepeatable(X509Svid.class, index);
        if (x509SvidInstances.isEmpty()) {
            return List.of();
        }
        if (capabilities.isMissing(Capability.TLS_REGISTRY)) {
            throw new ConfigurationException(
                    "@" + X509Svid.class.getSimpleName() + " requires the TLS registry extension (quarkus-tls-registry)");
        }
        List<X509SvidDeclarationBuildItem> declarations = new ArrayList<>();
        Set<String> tlsConfigurationNames = new HashSet<>();
        Map<String, String> tlsConfigurationNameBySpiffeId = new HashMap<>();
        for (AnnotationInstance annotationInstance : x509SvidInstances) {
            String tlsConfigurationName = annotationInstance.value("tls").asString();
            if (tlsConfigurationName.isBlank()) {
                throw new ConfigurationException("The 'tls' attribute of the @" + X509Svid.class.getSimpleName()
                        + " annotation on " + annotationInstance.target() + " must not be blank");
            }
            if (!tlsConfigurationNames.add(tlsConfigurationName)) {
                throw new ConfigurationException("The TLS configuration '" + tlsConfigurationName + "' is declared by more"
                        + " than one @" + X509Svid.class.getSimpleName() + " annotation, the names must be unique");
            }
            String spiffeId = annotationInstance.valueWithDefault(index, "spiffeId").asString();
            if (spiffeId == null) {
                spiffeId = SAME_TRUST_DOMAIN;
            }
            validateSpiffeIdAvailableAtBuildTime(tlsConfigurationName, spiffeId, tlsConfigurationNameBySpiffeId);
            declarations.add(new X509SvidDeclarationBuildItem(tlsConfigurationName, spiffeId));
        }
        return declarations;
    }

    @BuildStep(onlyIf = SpiffeClientEnabled.class)
    ServiceStartBuildItem initializeTlsConfigurations(List<X509SvidDeclarationBuildItem> declarations,
            ServiceRegistrar serviceRegistrar) {
        if (declarations.isEmpty()) {
            return null;
        }
        serviceRegistrar
                .forService("io.quarkus.spiffe.client.initialize-tls-configurations")
                .atPhase(Phase.DATA)
                .require(Vertx.class)
                .require(SpiffeClientConfig.class)
                .require(BeanContainer.class)
                .after(TlsConfigurationRegistry.class)
                // the first fetch instantiates the SpiffeClientImpl bean, which injects the runtime-init Vertx bean
                .afterBuildItem(SyntheticBeansRuntimeInitBuildItem.class)
                .before("io.quarkus.arc.startup-event")
                .onStartAsync((ctx, vertx, config, beanContainer) -> SpiffeTlsStoreProvider.start(vertx,
                        config.x509Svid().refreshPeriod(), ctx::onStop, i -> ctx.startComplete(), ctx::startFailed,
                        beanContainer.beanInstance(X509SvidClient.class)));
        return new ServiceStartBuildItem(FEATURE);
    }

    /**
     * Generates per declaration a store provider bean the TLS registry discovers by its qualifier:
     *
     * <pre>
     * &#64;Singleton
     * &#64;Identifier("keycloak")
     * final class SpiffeTlsStoreProvider_keycloak_1a2b3c4d extends SpiffeTlsStoreProvider {
     *     &#64;Inject
     *     public SpiffeTlsStoreProvider_keycloak_1a2b3c4d(X509SvidClient spiffeClient) {
     *         super("keycloak", "spiffe://example.org/keycloak", spiffeClient);
     *     }
     * }
     * </pre>
     *
     * A synthetic bean would not do, the registry collects the provider names at bean discovery, before synthetic beans
     * exist.
     */
    @BuildStep(onlyIf = SpiffeClientEnabled.class)
    void generateTlsStoreProviderBeans(List<X509SvidDeclarationBuildItem> declarations,
            BuildProducer<GeneratedBeanBuildItem> generatedBeans,
            BuildProducer<ConstantBootstrapBuildItem> constantBootstraps) {
        if (declarations.isEmpty()) {
            return;
        }
        Gizmo gizmo = Gizmo.create(new GeneratedBeanGizmo2Adaptor(generatedBeans, constantBootstraps));
        ConstructorDesc providerConstructor = ConstructorDesc.of(SpiffeTlsStoreProvider.class, String.class, String.class,
                X509SvidClient.class);
        for (X509SvidDeclarationBuildItem declaration : declarations) {
            gizmo.class_(providerBeanClassName(declaration.tlsConfigurationName), cc -> {
                cc.final_();
                cc.extends_(SpiffeTlsStoreProvider.class);
                cc.addAnnotation(Singleton.class);
                cc.addAnnotation(Identifier.class, ac -> ac.add("value", declaration.tlsConfigurationName));
                cc.constructor(constructor -> {
                    constructor.public_();
                    constructor.addAnnotation(Inject.class);
                    ParamVar spiffeClient = constructor.parameter("spiffeClient", pc -> pc.setType(X509SvidClient.class));
                    constructor.body(bc -> {
                        bc.invokeSpecial(providerConstructor, cc.this_(), Const.of(declaration.tlsConfigurationName),
                                Const.of(declaration.spiffeId), spiffeClient);
                        bc.return_();
                    });
                });
            });
        }
    }

    private static String providerBeanClassName(String tlsConfigurationName) {
        // the sanitized name keeps stack traces readable, the digest keeps the class name unique
        return SpiffeTlsStoreProvider.class.getName() + "_" + tlsConfigurationName.replaceAll("[^A-Za-z0-9_]", "_") + "_"
                + HexFormat.of().formatHex(sha256(tlsConfigurationName), 0, 8);
    }

    private static byte[] sha256(String value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static void validateSpiffeIdAvailableAtBuildTime(String tlsConfigurationName, String spiffeId,
            Map<String, String> tlsConfigurationNameBySpiffeId) {
        if (spiffeId.contains("${")) {
            // expanded and validated at runtime by SpiffeTlsStoreProvider
            return;
        }
        if (!SAME_TRUST_DOMAIN.equals(spiffeId)) {
            try {
                SpiffeValidator.validateSpiffeId(spiffeId);
            } catch (SpiffeConnectionException e) {
                throw new ConfigurationException("Invalid peer SPIFFE ID '" + spiffeId + "' of the TLS configuration '"
                        + tlsConfigurationName + "': " + e.getMessage(), e);
            }
        }
        String otherTlsConfigurationName = tlsConfigurationNameBySpiffeId.putIfAbsent(spiffeId, tlsConfigurationName);
        if (otherTlsConfigurationName != null) {
            String peer = SAME_TRUST_DOMAIN.equals(spiffeId) ? "any workload of the trust domain"
                    : "the SPIFFE ID '" + spiffeId + "'";
            throw new ConfigurationException("The TLS configurations '" + otherTlsConfigurationName + "' and '"
                    + tlsConfigurationName + "' both authorize " + peer + ", each @" + X509Svid.class.getSimpleName()
                    + " declaration must authorize a different peer");
        }
    }

    private static final class X509SvidDeclarationBuildItem extends MultiBuildItem {

        final String tlsConfigurationName;
        final String spiffeId;

        X509SvidDeclarationBuildItem(String tlsConfigurationName, String spiffeId) {
            this.tlsConfigurationName = tlsConfigurationName;
            this.spiffeId = spiffeId;
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
