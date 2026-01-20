package io.quarkus.security.spi.runtime;

import io.quarkus.registry.ValueRegistry;
import io.quarkus.runtime.BlockingOperationControl;
import io.quarkus.runtime.BlockingOperationNotAllowedException;
import io.quarkus.security.identity.CurrentIdentityAssociation;
import io.quarkus.security.identity.IdentityProviderManager;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.request.AnonymousAuthenticationRequest;
import io.smallrye.mutiny.Uni;

public abstract class AbstractSecurityIdentityAssociation implements CurrentIdentityAssociation {

    /**
     * {@link ValueRegistry} key that allows extensions to register their own request-scoped delegate
     * to the @TestSecurity identity association.
     * This only makes sense in very special cases, like in case of WebSockets Next, when the identity provided
     * by authentication mechanisms is stored on the WebSocket connection.
     */
    public static ValueRegistry.RuntimeKey<CurrentIdentityAssociation> TEST_SECURITY_DELEGATE_RUNTIME_KEY = ValueRegistry.RuntimeKey
            .key("io.quarkus.test.security.delegate-identity-association", CurrentIdentityAssociation.class);

    private volatile SecurityIdentity identity;
    private volatile Uni<SecurityIdentity> deferredIdentity;

    protected abstract IdentityProviderManager getIdentityProviderManager();

    @Override
    public void setIdentity(SecurityIdentity identity) {
        this.identity = identity;
        this.deferredIdentity = null;
    }

    @Override
    public void setIdentity(Uni<SecurityIdentity> identity) {
        this.identity = null;
        this.deferredIdentity = identity;
    }

    public Uni<SecurityIdentity> getDeferredIdentity() {
        if (deferredIdentity != null) {
            return deferredIdentity;
        } else if (identity != null) {
            return Uni.createFrom().item(identity);
        } else {
            return deferredIdentity = getIdentityProviderManager().authenticate(AnonymousAuthenticationRequest.INSTANCE);
        }
    }

    @Override
    public SecurityIdentity getIdentity() {
        if (identity == null) {
            if (deferredIdentity != null) {
                if (BlockingOperationControl.isBlockingAllowed()) {
                    identity = deferredIdentity.await().indefinitely();
                } else {
                    throw new BlockingOperationNotAllowedException(
                            "Cannot call getIdentity() from the IO thread when lazy authentication " +
                                    "is in use, as resolving the identity may block the thread. Instead you should inject the "
                                    +
                                    "CurrentIdentityAssociation, call CurrentIdentityAssociation#getDeferredIdentity() and " +
                                    "subscribe to the Uni.");
                }
            }
            if (identity == null) {
                identity = getIdentityProviderManager().authenticate(AnonymousAuthenticationRequest.INSTANCE).await()
                        .indefinitely();
            }
        }
        return identity;
    }

}
