package io.quarkus.security.runtime.interceptor;

import static io.quarkus.security.spi.runtime.SecurityHandlerConstants.SECURITY_INTERCEPTOR_PRIORITY;

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
public class RunAsUserInterceptor {

    @Inject
    CurrentIdentityAssociation identityAssociation;

    @AroundInvoke
    public Object intercept(InvocationContext ic) throws Exception {
        System.out.println("////////// run as user //////////////////////");
        RunAsUser runAsUser = ic.getInterceptorBinding(RunAsUser.class);
        // FIXME: this must be either switch or validate that previously there was no identity?
        // FIXME: is there always active CDI request context for scheduled methods?
        // FIXME: roles!
        identityAssociation
                .setIdentity(QuarkusSecurityIdentity.builder().setPrincipal(new QuarkusPrincipal(runAsUser.user())).build());
        return ic.proceed();
    }
}
