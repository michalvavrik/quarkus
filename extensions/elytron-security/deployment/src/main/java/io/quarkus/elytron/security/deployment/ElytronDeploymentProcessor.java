package io.quarkus.elytron.security.deployment;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.jboss.logging.Logger;
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
 * with the Elytron security services. The {@linkplain SecurityRealm}s declared by the Elytron realm extensions
 * (properties file, JDBC, LDAP and OAuth2) with {@link ElytronSecurityRealmBuildItem}s are combined into a single
 * {@linkplain SecurityDomain}, which is then handed over to the Elytron identity providers.
 *
 * TODO: The handling of the configuration to SecurityRealm instance creation/loading is clumsy to not being able to
 * have a config object annotated with @ConfigGroup inherit from another object with MP config annotated properties.
 *
 */
class ElytronDeploymentProcessor {

    private static final Logger log = Logger.getLogger(ElytronDeploymentProcessor.class);

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
     * Create the deployment SecurityDomain from the SecurityRealms declared by the realm extensions.
     * <p>
     * The realms are added to the domain in the build item order, with the realms requiring the bean container last,
     * and the first realm becomes the default realm of the domain, see {@link ElytronSecurityRealmBuildItem}. Elytron
     * only supports one realm per realm name, so a realm added later replaces an earlier realm with the same name,
     * which is reported as a warning.
     */
    @BuildStep
    void build(ServiceRegistrar serviceRegistrar, List<ElytronSecurityRealmBuildItem> realms) {
        List<ElytronSecurityRealmBuildItem> orderedRealms = new ArrayList<>(realms.size());
        for (ElytronSecurityRealmBuildItem realm : realms) {
            if (!realm.requiresBeanContainer) {
                orderedRealms.add(realm);
            }
        }
        for (ElytronSecurityRealmBuildItem realm : realms) {
            if (realm.requiresBeanContainer) {
                orderedRealms.add(realm);
            }
        }
        warnAboutDuplicateRealmNames(orderedRealms);

        List<String> serviceNames = orderedRealms.stream().map(ElytronSecurityRealmBuildItem::getServiceName).toList();
        List<String> realmNames = orderedRealms.stream().map(ElytronSecurityRealmBuildItem::getRealmName).toList();
        serviceRegistrar.forService(SecurityDomain.class)
                .atPhase(Phase.INIT)
                .consumeAll(SecurityRealm.class)
                .after(BeanContainer.class)
                .optional()
                .onStart((ctx, securityRealms) -> ElytronRecorder.buildDomain(serviceNames, realmNames, securityRealms));
    }

    private static void warnAboutDuplicateRealmNames(List<ElytronSecurityRealmBuildItem> orderedRealms) {
        Map<String, ElytronSecurityRealmBuildItem> realmsByName = new HashMap<>();
        for (ElytronSecurityRealmBuildItem realm : orderedRealms) {
            ElytronSecurityRealmBuildItem replacedRealm = realmsByName.put(realm.realmName, realm);
            if (replacedRealm != null) {
                log.warnf("The realm name '%s' is used by both %s and %s, so only the realm of %s is added to the"
                        + " security domain. Configure a different realm name for one of them to use both realms.",
                        realm.realmName, replacedRealm.describe(), realm.describe(), realm.describe());
            }
        }
    }

    @BuildStep
    void setDomainForIdentityProvider(ServiceRegistrar serviceRegistrar) {
        serviceRegistrar.forService("io.quarkus.elytron-security.set-domain-for-identity-provider")
                .atPhase(Phase.INIT) // same phase as the SecurityDomain service, set as soon as the domain is available
                .require(BeanContainer.class)
                .request(SecurityDomain.class)
                // TODO: when Vert.x HTTP Security is migrated, we should migrate this 'before' to its init service
                //      until then, this is fine since the HTTP router socket is only opened after the startup event
                //      and this security domain is currently not needed before the first HTTP request
                .before("io.quarkus.arc.startup-event")
                .onStart((ctx, bc, securityDomain) -> securityDomain
                        .ifPresent(domain -> ElytronRecorder.setDomainForIdentityProvider(bc, domain)));
    }

}
