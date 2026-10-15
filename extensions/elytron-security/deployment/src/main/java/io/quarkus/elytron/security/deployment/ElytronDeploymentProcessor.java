package io.quarkus.elytron.security.deployment;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityRealm;

import io.quarkus.arc.deployment.AdditionalBeanBuildItem;
import io.quarkus.arc.runtime.BeanContainer;
import io.quarkus.core.Phase;
import io.quarkus.core.deployment.service.ServiceRegistrar;
import io.quarkus.deployment.annotations.BuildProducer;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.elytron.security.runtime.DefaultRoleDecoder;
import io.quarkus.elytron.security.runtime.ElytronPasswordIdentityProvider;
import io.quarkus.elytron.security.runtime.ElytronRecorder;
import io.quarkus.elytron.security.runtime.ElytronSecurityDomainManager;
import io.quarkus.elytron.security.runtime.ElytronTokenIdentityProvider;
import io.quarkus.elytron.security.runtime.ElytronTrustedIdentityProvider;

/**
 * The build time process for the security aspects of the deployment. This creates {@linkplain BuildStep}s for integration
 * with the Elytron security services. This supports the Elytron
 * {@linkplain org.wildfly.security.auth.realm.LegacyPropertiesSecurityRealm}
 * and {@linkplain org.wildfly.security.auth.realm.SimpleMapBackedSecurityRealm} realm implementations. Others could be
 * added by creating an extension that produces a SecurityRealmBuildItem for the realm.
 *
 * Additional authentication mechanisms can be added by producing AuthConfigBuildItems and including the associated
 * {@linkplain io.undertow.servlet.ServletExtension} implementations to register the
 * {@linkplain io.undertow.security.api.AuthenticationMechanismFactory}.
 *
 * TODO: The handling of the configuration to SecurityRealm instance creation/loading is clumsy to not being able to
 * have a config object annotated with @ConfigGroup inherit from another object with MP config annotated properties.
 *
 */
class ElytronDeploymentProcessor {

    @BuildStep
    void addBeans(BuildProducer<AdditionalBeanBuildItem> beans, List<ElytronPasswordMarkerBuildItem> pw,
            List<ElytronTokenMarkerBuildItem> token) {
        beans.produce(AdditionalBeanBuildItem.unremovableOf(ElytronSecurityDomainManager.class));
        beans.produce(AdditionalBeanBuildItem.unremovableOf(DefaultRoleDecoder.class));
        if (!token.isEmpty()) {
            beans.produce(AdditionalBeanBuildItem.unremovableOf(ElytronTokenIdentityProvider.class));
        }
        if (!pw.isEmpty()) {
            beans.produce(AdditionalBeanBuildItem.unremovableOf(ElytronPasswordIdentityProvider.class));
            beans.produce(AdditionalBeanBuildItem.unremovableOf(ElytronTrustedIdentityProvider.class));
        }
    }

    /**
     * Create the deployment SecurityDomain using the SecurityRealms that have been created.
     */
    @BuildStep
    void build(ServiceRegistrar serviceRegistrar) {
        serviceRegistrar.forService(SecurityDomain.class)
                .atPhase(Phase.INIT)
                .consumeAll(SecurityRealm.class)
                .after(BeanContainer.class)
                .optional()
                .onStart((ctx, nameToSecurityRealm) -> {
                    if (nameToSecurityRealm.isEmpty()) {
                        return Optional.empty();
                    }
                    SecurityDomain.Builder securityDomainBuilder = null;
                    for (Map.Entry<String, SecurityRealm> e : nameToSecurityRealm.entrySet()) {
                        if (securityDomainBuilder == null) {
                            securityDomainBuilder = ElytronRecorder.configureDomainBuilder(e.getKey(), e.getValue());
                        } else {
                            ElytronRecorder.addRealm(securityDomainBuilder, e.getKey(), e.getValue());
                        }
                    }
                    return Optional.of(securityDomainBuilder.build());
                });
    }

    @BuildStep
    void setDomainForIdentityProvider(ServiceRegistrar serviceRegistrar) {
        serviceRegistrar.forService("io.quarkus.elytron.security.deployment.set-domain-for-identity-provider")
                .atPhase(Phase.DATA) // set as soon as SecurityDomain is available
                .require(BeanContainer.class)
                .request(SecurityDomain.class)
                .onStart((ctx, bc, securityDomain) -> securityDomain
                        .ifPresent(domain -> ElytronRecorder.setDomainForIdentityProvider(bc, domain)));
    }

}
