package io.quarkus.security.jpa.runtime;

import java.util.Collection;
import java.util.List;

import jakarta.inject.Inject;

import io.quarkus.security.identity.IdentityProvider;
import io.quarkus.security.jpa.SecurityJpa;

public final class SecurityJpaImpl implements SecurityJpa {

    @Inject
    JpaIdentityProvider jpaIdentityProvider;

    @Inject
    JpaTrustedIdentityProvider jpaTrustedIdentityProvider;

    @Override
    public Collection<IdentityProvider<?>> getIdentityProviders() {
        return List.of(jpaIdentityProvider, jpaTrustedIdentityProvider);
    }

}
