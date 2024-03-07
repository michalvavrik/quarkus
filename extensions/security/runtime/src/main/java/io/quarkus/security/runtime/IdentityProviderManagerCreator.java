package io.quarkus.security.runtime;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executor;
import java.util.function.Supplier;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Instance;
import jakarta.enterprise.inject.Produces;
import jakarta.inject.Inject;

import io.quarkus.arc.DefaultBean;
import io.quarkus.runtime.ExecutorRecorder;
import io.quarkus.security.identity.AuthenticationRequestContext;
import io.quarkus.security.identity.IdentityProvider;
import io.quarkus.security.identity.IdentityProviderManager;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.SecurityIdentityAugmentor;
import io.quarkus.security.identity.request.AnonymousAuthenticationRequest;
import io.quarkus.security.spi.runtime.BlockingSecurityExecutor;
import io.smallrye.mutiny.Uni;

/**
 * CDI bean than manages the lifecycle of the {@link io.quarkus.security.identity.IdentityProviderManager}
 */
@ApplicationScoped
public class IdentityProviderManagerCreator {

    @Inject
    Instance<IdentityProvider<?>> identityProviders;

    @Inject
    Instance<SecurityIdentityAugmentor> augmentors;

    @Inject
    BlockingSecurityExecutor blockingExecutor;

    @Inject
    SecurityConfig securityConfig;

    @ApplicationScoped
    @DefaultBean
    @Produces
    BlockingSecurityExecutor defaultBlockingExecutor() {
        return BlockingSecurityExecutor.createBlockingExecutor(new Supplier<Executor>() {
            @Override
            public Executor get() {
                return ExecutorRecorder.getCurrent();
            }
        });
    }

    @Produces
    @ApplicationScoped
    public IdentityProviderManager ipm() {
        boolean customAnon = false;
        QuarkusIdentityProviderManagerImpl.Builder builder = QuarkusIdentityProviderManagerImpl.builder();
        for (IdentityProvider i : identityProviders) {
            builder.addProvider(i);
            if (i.getRequestType() == AnonymousAuthenticationRequest.class) {
                customAnon = true;
            }
        }
        if (!customAnon) {
            builder.addProvider(new AnonymousIdentityProvider());
        }
        for (SecurityIdentityAugmentor i : augmentors) {
            builder.addSecurityIdentityAugmentor(i);
        }
        if (!securityConfig.roles().isEmpty()) {
            builder.addSecurityIdentityAugmentor(createRoleMappingAugmentor(securityConfig.roles()));
        }
        builder.setBlockingExecutor(blockingExecutor);
        return builder.build();
    }

    /**
     * Maps roles possessed by the {@link SecurityIdentity} to new roles.
     */
    private static SecurityIdentityAugmentor createRoleMappingAugmentor(Map<String, Set<String>> possessedRoleToNewRoles) {
        return new SecurityIdentityAugmentor() {
            @Override
            public Uni<SecurityIdentity> augment(SecurityIdentity identity,
                    AuthenticationRequestContext authenticationRequestContext) {
                if (!identity.isAnonymous()) {
                    QuarkusSecurityIdentity.Builder builder = null;
                    for (var e : possessedRoleToNewRoles.entrySet()) {
                        if (identity.hasRole(e.getKey())) {
                            if (builder == null) {
                                builder = QuarkusSecurityIdentity.builder(identity);
                            }
                            builder.addRoles(e.getValue());
                        }
                    }
                    if (builder != null) {
                        return Uni.createFrom().item(builder.build());
                    }
                }
                return Uni.createFrom().item(identity);
            }

            @Override
            public int priority() {
                // we want to be able to re-map roles granted to the identity by other augmentors
                // yet to give user option to make adjustments in the edge scenarios => run almost last
                return Integer.MAX_VALUE - 100;
            }
        };
    }
}
