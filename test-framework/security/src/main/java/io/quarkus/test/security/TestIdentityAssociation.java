package io.quarkus.test.security;

import static io.quarkus.security.spi.runtime.AbstractSecurityIdentityAssociation.TEST_SECURITY_DELEGATE_RUNTIME_KEY;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.Priority;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.context.RequestScoped;
import jakarta.enterprise.inject.Alternative;
import jakarta.inject.Inject;
import jakarta.interceptor.Interceptor;

import io.quarkus.registry.ValueRegistry;
import io.quarkus.runtime.LaunchMode;
import io.quarkus.security.identity.CurrentIdentityAssociation;
import io.quarkus.security.identity.IdentityProviderManager;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.spi.runtime.AbstractSecurityIdentityAssociation;
import io.smallrye.mutiny.Uni;

@Alternative
@Priority(Interceptor.Priority.LIBRARY_AFTER)
@ApplicationScoped
public class TestIdentityAssociation implements CurrentIdentityAssociation {

    private volatile SecurityIdentity testIdentity;

    /**
     * Whether authentication is successful only if right mechanism was used to authenticate.
     */
    private volatile boolean isPathBasedIdentity = false;

    /**
     * A request scoped delegate that allows the system to function as normal when
     * the user has not been explicitly overridden
     */
    private final CurrentIdentityAssociation delegate;

    // used for JUnit test verifying this bean
    TestIdentityAssociation(CurrentIdentityAssociation delegate) {
        this.delegate = delegate;
    }

    @Inject
    TestIdentityAssociation(ValueRegistry valueRegistry, DelegateSecurityIdentityAssociation defaultDelegate) {
        this.delegate = valueRegistry.getOrDefault(TEST_SECURITY_DELEGATE_RUNTIME_KEY, defaultDelegate);
    }

    @PostConstruct
    public void check() {
        if (LaunchMode.current() != LaunchMode.TEST) {
            //paranoid check
            throw new RuntimeException("TestAuthController can only be used in tests");
        }
    }

    public SecurityIdentity getTestIdentity() {
        return testIdentity;
    }

    public TestIdentityAssociation setTestIdentity(SecurityIdentity testIdentity) {
        this.testIdentity = testIdentity;
        return this;
    }

    @Override
    public void setIdentity(SecurityIdentity identity) {
        delegate.setIdentity(identity);
    }

    @Override
    public void setIdentity(Uni<SecurityIdentity> identity) {
        delegate.setIdentity(identity);
    }

    @Override
    public Uni<SecurityIdentity> getDeferredIdentity() {
        if (testIdentity == null) {
            return delegate.getDeferredIdentity();
        }
        return delegate.getDeferredIdentity().onItem()
                .transform(underlying -> underlying.isAnonymous() && !isPathBasedIdentity ? testIdentity : underlying);
    }

    @Override
    public SecurityIdentity getIdentity() {
        //we check the underlying identity first
        //in most cases this will have been set by the TestHttpAuthenticationMechanism
        //this means that all the usual auth process will run, including augmentors and
        //the identity ends up in the routing context
        SecurityIdentity underlying = delegate.getIdentity();
        if (underlying.isAnonymous()) {
            if (testIdentity != null && !isPathBasedIdentity) {
                return testIdentity;
            }
        }
        return underlying;
    }

    void setPathBasedIdentity(boolean pathBasedIdentity) {
        isPathBasedIdentity = pathBasedIdentity;
    }

}

@RequestScoped
class DelegateSecurityIdentityAssociation extends AbstractSecurityIdentityAssociation {

    @Inject
    IdentityProviderManager identityProviderManager;

    @Override
    protected IdentityProviderManager getIdentityProviderManager() {
        return identityProviderManager;
    }
}
