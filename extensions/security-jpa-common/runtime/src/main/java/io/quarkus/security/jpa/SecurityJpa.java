package io.quarkus.security.jpa;

import io.quarkus.arc.Arc;
import io.quarkus.security.identity.IdentityProvider;
import io.quarkus.security.spi.runtime.IdentityProviderBuilder;
import io.smallrye.common.annotation.Experimental;

/**
 * A CDI bean used to build Quarkus Security JPA {@link IdentityProvider}s programmatically.
 * This bean should be used together with the CDI event 'HttpSecurity' when you
 * want to configure the Basic or Form authentication to use the Quarkus Security {@link IdentityProvider}.
 */
@Experimental("This API is currently experimental and might get changed")
public interface SecurityJpa extends IdentityProviderBuilder {

    /**
     * Selects the persistence unit used by the Security JPA identity providers.
     *
     * @param persistenceUnitName persistence unit name
     * @return {@link SecurityJpa}
     */
    SecurityJpa persistence(String persistenceUnitName);

    /**
     * Looks up the {@link SecurityJpa} builder and returns it.
     *
     * @return {@link SecurityJpa}
     */
    static SecurityJpa jpa() {
        return Arc.requireContainer().instance(SecurityJpa.class).get();
    }
}
