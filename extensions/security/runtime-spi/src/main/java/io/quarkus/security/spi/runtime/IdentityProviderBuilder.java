package io.quarkus.security.spi.runtime;

import java.util.Collection;

import io.quarkus.security.identity.IdentityProvider;
import io.smallrye.common.annotation.Experimental;

/**
 * Builder API which allows extensions like the Quarkus Security JPA to create {@link IdentityProvider}s
 * programmatically. This builder is used together with the CDI event 'HttpSecurity'.
 */
@Experimental("This API is currently experimental and might get changed")
public interface IdentityProviderBuilder {

    /**
     * @return {@link IdentityProvider}s; never null
     */
    Collection<IdentityProvider<?>> identityProviders();

}
