package io.quarkus.elytron.security.common.deployment;

import io.quarkus.core.Phase;
import io.quarkus.core.deployment.service.ServiceRegistrar;
import io.quarkus.deployment.annotations.BuildProducer;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.builditem.ModuleExportBuildItem;
import io.quarkus.deployment.builditem.nativeimage.ReflectiveClassBuildItem;
import io.quarkus.deployment.builditem.nativeimage.RuntimeInitializedClassBuildItem;
import io.quarkus.elytron.security.common.BcryptUtil;
import io.quarkus.elytron.security.common.runtime.ElytronCommonRecorder;
import io.quarkus.modular.spi.items.AddDependencyBuildItem;
import io.smallrye.modules.desc.Dependency.Modifier;

public class QuarkusSecurityCommonProcessor {
    @BuildStep
    void exportPasswordImplementations(BuildProducer<ModuleExportBuildItem> exports) {
        exports.produce(new ModuleExportBuildItem("org.wildfly.security.wildfly.elytron.password.impl",
                "org.wildfly.security.wildfly.elytron.credential", "org.wildfly.security.password.impl"));
        // the password provider also advertises the SHA-512-256 MessageDigest implemented by the digest module
        exports.produce(new ModuleExportBuildItem("org.wildfly.security.wildfly.elytron.digest",
                "org.wildfly.security.wildfly.elytron.credential", "org.wildfly.security.digest"));
    }

    @BuildStep
    void linkPasswordProviderToImplementations(BuildProducer<AddDependencyBuildItem> dependencies) {
        dependencies.produce(new AddDependencyBuildItem("org.wildfly.security.wildfly.elytron.credential",
                "org.wildfly.security.wildfly.elytron.password.impl", Modifier.Set.of(Modifier.READ, Modifier.LINKED)));
        dependencies.produce(new AddDependencyBuildItem("org.wildfly.security.wildfly.elytron.credential",
                "org.wildfly.security.wildfly.elytron.digest", Modifier.Set.of(Modifier.READ, Modifier.LINKED)));
    }

    @BuildStep
    RuntimeInitializedClassBuildItem runtimeInitBcryptUtil() {
        // this holds a SecureRandom static var that needs to be initialised at run time
        return new RuntimeInitializedClassBuildItem(BcryptUtil.class.getName());
    }

    @BuildStep
    public void registerPasswordProvider(ServiceRegistrar reg) {
        reg
                .forService("io.quarkus.elytron-security-common.password-provider")
                .atPhase(Phase.STATIC_INIT)
                .onStart(ctx -> ElytronCommonRecorder.registerPasswordProvider());
    }

    /**
     * Graal VM now seems to lose providers registered at static init.
     * We re-register at runtime (which is a no-op in JVM mode).
     */
    @BuildStep
    public void registerPasswordProviderForNative(ServiceRegistrar reg) {
        reg
                .forService("io.quarkus.elytron-security-common.password-provider-native")
                .atPhase(Phase.INFRASTRUCTURE)
                .onStart(ctx -> ElytronCommonRecorder.registerPasswordProvider());
    }

    /**
     * Register the Elytron-provided password factory SPI implementation and the SHA-512-256 message digest,
     * both of which the password provider instantiates reflectively
     *
     * @param classes producer factory for ReflectiveClassBuildItems
     */
    @BuildStep
    void services(BuildProducer<ReflectiveClassBuildItem> classes) {
        classes.produce(ReflectiveClassBuildItem.builder("org.wildfly.security.password.impl.PasswordFactorySpiImpl")
                .reason(getClass().getName())
                .methods().build());
        classes.produce(ReflectiveClassBuildItem.builder("org.wildfly.security.digest.SHA512_256MessageDigest")
                .reason(getClass().getName())
                .build());
    }
}
