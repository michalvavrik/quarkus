package io.quarkus.security.jpa.reactive.runtime;

import static io.quarkus.hibernate.orm.runtime.PersistenceUnitUtil.DEFAULT_PERSISTENCE_UNIT_NAME;

import java.util.Collection;
import java.util.List;
import java.util.Objects;

import jakarta.enterprise.inject.Any;
import jakarta.enterprise.inject.Instance;
import jakarta.enterprise.inject.Produces;

import org.hibernate.reactive.mutiny.Mutiny;

import io.quarkus.hibernate.orm.PersistenceUnit;
import io.quarkus.security.identity.IdentityProvider;
import io.quarkus.security.jpa.SecurityJpa;

public class SecurityJpaReactiveProvider {

    @Produces
    SecurityJpa createSecurityJpa(@Any Instance<Mutiny.SessionFactory> sessionFactoryInstance) {
        return new SecurityJpa() {

            private String persistenceUnitName = DEFAULT_PERSISTENCE_UNIT_NAME;

            @Override
            public Collection<IdentityProvider<?>> identityProviders() {
                final Mutiny.SessionFactory sessionFactory;
                if (DEFAULT_PERSISTENCE_UNIT_NAME.equals(persistenceUnitName)) {
                    sessionFactory = sessionFactoryInstance.get();
                } else {
                    sessionFactory = getNamedSessionFactoryInstance().get();
                }
                var jpaIdentityProvider = newJpaIdentityProvider();
                jpaIdentityProvider.sessionFactory = sessionFactory;
                var trustedIdentityProvider = newJpaTrustedIdentityProvider();
                trustedIdentityProvider.sessionFactory = sessionFactory;

                return List.of(jpaIdentityProvider, trustedIdentityProvider);
            }

            private Instance<Mutiny.SessionFactory> getNamedSessionFactoryInstance() {
                return sessionFactoryInstance.select(new PersistenceUnit.PersistenceUnitLiteral(persistenceUnitName));
            }

            @Override
            public SecurityJpa persistence(String persistenceUnitName) {
                this.persistenceUnitName = Objects.requireNonNull(persistenceUnitName);
                if (!getNamedSessionFactoryInstance().isResolvable()) {
                    throw new IllegalArgumentException("Unknown persistence unit '%s'".formatted(persistenceUnitName));
                }
                return this;
            }
        };
    }

    private static native JpaReactiveIdentityProvider newJpaIdentityProvider();

    private static native JpaReactiveTrustedIdentityProvider newJpaTrustedIdentityProvider();
}
