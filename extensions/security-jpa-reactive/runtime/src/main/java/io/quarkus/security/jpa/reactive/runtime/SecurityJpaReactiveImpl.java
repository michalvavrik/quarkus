package io.quarkus.security.jpa.reactive.runtime;

import java.util.Collection;
import java.util.List;

import jakarta.inject.Inject;

import io.quarkus.security.identity.IdentityProvider;
import io.quarkus.security.jpa.SecurityJpa;

public final class SecurityJpaReactiveImpl implements SecurityJpa {

    @Inject
    JpaReactiveIdentityProvider jpaReactiveIdentityProvider;

    @Inject
    JpaReactiveTrustedIdentityProvider jpaReactiveTrustedIdentityProvider;

    @Override
    public Collection<IdentityProvider<?>> getIdentityProviders() {
        return List.of(jpaReactiveIdentityProvider, jpaReactiveTrustedIdentityProvider);
    }

}
