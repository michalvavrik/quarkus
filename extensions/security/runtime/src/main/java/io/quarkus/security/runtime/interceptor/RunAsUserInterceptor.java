package io.quarkus.security.runtime.interceptor;

import static io.quarkus.security.spi.runtime.SecurityHandlerConstants.SECURITY_INTERCEPTOR_PRIORITY;

import java.util.Set;

import jakarta.annotation.Priority;
import jakarta.inject.Inject;
import jakarta.interceptor.AroundInvoke;
import jakarta.interceptor.Interceptor;
import jakarta.interceptor.InvocationContext;

import io.quarkus.arc.Arc;
import io.quarkus.security.identity.CurrentIdentityAssociation;
import io.quarkus.security.identity.RunAsUser;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.smallrye.mutiny.Uni;

@Interceptor
@Priority(SECURITY_INTERCEPTOR_PRIORITY)
public final class RunAsUserInterceptor {

    @Inject
    CurrentIdentityAssociation identityAssociation;

    @AroundInvoke
    Object intercept(InvocationContext ic) throws Exception {
        Class<?> returnType = ic.getMethod().getReturnType();
        if (returnType == void.class || returnType == Void.class) {
            configureIdentityFromAnnotation(ic);
            try {
                return ic.proceed();
            } finally {
                cleanIdentity();
            }
        } else if (Uni.class.isAssignableFrom(returnType)) {
            // this is 'Uni<Void>' according to the build-time validation
            return Uni.createFrom().emitter(emitter -> {
                configureIdentityFromAnnotation(ic);
                try {
                    var uni = (Uni<?>) ic.proceed();
                    uni.subscribe().with(item -> {
                        cleanIdentity();
                        emitter.complete(new Object());
                    }, failure -> {
                        cleanIdentity();
                        emitter.fail(failure);
                    });
                } catch (Exception exception) {
                    cleanIdentity();
                    emitter.fail(exception);
                }
            }).replaceWithVoid();
        } else {
            // we validate this during the build time, therefore this should never happen
            throw new IllegalStateException("Unsupported return type " + returnType);
        }
    }

    private void configureIdentityFromAnnotation(InvocationContext ic) {
        var runAsUser = ic.getInterceptorBinding(RunAsUser.class);
        var identityBuilder = QuarkusSecurityIdentity.builder().setPrincipal(new QuarkusPrincipal(runAsUser.user()));
        if (runAsUser.roles() != null && runAsUser.roles().length > 0) {
            identityBuilder.addRoles(Set.of(runAsUser.roles()));
        }
        identityAssociation.setIdentity(identityBuilder.build());
    }

    private void cleanIdentity() {
        var container = Arc.container();
        if (container != null && container.requestContext().isActive()) {
            // this shouldn't be necessary for scheduled methods, but theoretically someone can register
            // their own annotation for non-scheduled methods, so let's clear the identity association
            identityAssociation.setIdentity((SecurityIdentity) null);
        }
    }
}
