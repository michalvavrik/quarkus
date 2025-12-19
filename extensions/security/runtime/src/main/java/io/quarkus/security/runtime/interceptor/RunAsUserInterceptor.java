package io.quarkus.security.runtime.interceptor;

import static io.quarkus.security.spi.runtime.SecurityHandlerConstants.SECURITY_INTERCEPTOR_PRIORITY;

import java.util.Set;

import jakarta.annotation.Priority;
import jakarta.inject.Inject;
import jakarta.interceptor.AroundInvoke;
import jakarta.interceptor.Interceptor;
import jakarta.interceptor.InvocationContext;

import io.quarkus.security.identity.CurrentIdentityAssociation;
import io.quarkus.security.identity.RunAsUser;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;

@Interceptor
@Priority(SECURITY_INTERCEPTOR_PRIORITY)
public final class RunAsUserInterceptor {

    @Inject
    CurrentIdentityAssociation identityAssociation;

    @AroundInvoke
    Object intercept(InvocationContext ic) throws Exception {
        var runAsUser = ic.getInterceptorBinding(RunAsUser.class);
        var identityBuilder = QuarkusSecurityIdentity.builder().setPrincipal(new QuarkusPrincipal(runAsUser.user()));
        if (runAsUser.roles() != null && runAsUser.roles().length > 0) {
            identityBuilder.addRoles(Set.of(runAsUser.roles()));
        }
        identityAssociation.setIdentity(identityBuilder.build());
        return ic.proceed();
    }
}
