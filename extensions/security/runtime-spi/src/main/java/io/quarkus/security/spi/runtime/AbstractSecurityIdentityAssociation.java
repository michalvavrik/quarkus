package io.quarkus.security.spi.runtime;

import io.quarkus.runtime.BlockingOperationControl;
import io.quarkus.runtime.BlockingOperationNotAllowedException;
import io.quarkus.security.identity.CurrentIdentityAssociation;
import io.quarkus.security.identity.IdentityProviderManager;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.request.AnonymousAuthenticationRequest;
import io.smallrye.mutiny.Uni;

/**
 * Parent for Quarkus builtin {@link CurrentIdentityAssociation}s, which prevents code duplications.
 * All the implementations must be {@link jakarta.enterprise.context.RequestScoped} which is when this parent is thread-safe.
 *
 * @see CurrentIdentityAssociation for more information
 */
public abstract class AbstractSecurityIdentityAssociation implements CurrentIdentityAssociation {

    private volatile SecurityIdentity identity;
    private volatile Uni<SecurityIdentity> deferredIdentity;

    /**
     * Returns the {@link IdentityProviderManager}.
     *
     * @return {@link IdentityProviderManager}
     */
    protected abstract IdentityProviderManager getIdentityProviderManager();

    /**
     * Sets current deferred SecurityIdentity} and replaces any previous values set by this method
     * and {@link #setIdentity(Uni)}. This method should typically be used early when the CDI request
     * context is activated and not change during the request.
     *
     * @param identity The new identity
     * @see CurrentIdentityAssociation#setIdentity(Uni)
     */
    @Override
    public void setIdentity(SecurityIdentity identity) {
        this.identity = identity;
        this.deferredIdentity = null;
    }

    /**
     * Sets current deferred {@link SecurityIdentity} and replaces any previous values set by this method
     * and {@link #setIdentity(SecurityIdentity)}. This method should typically be used early when the CDI request
     * context is activated and not change during the request.
     *
     * @param identity The new identity
     * @see CurrentIdentityAssociation#setIdentity(Uni)
     */
    @Override
    public void setIdentity(Uni<SecurityIdentity> identity) {
        this.identity = null;
        this.deferredIdentity = identity;
    }

    /**
     * Retrieves a {@link SecurityIdentity} only resolved when the returned {@link Uni} is subscribed.
     * Subscribing to the deferred identity may trigger authentication if the user isn't already authenticated.
     * Most of the time, the authentication only happens once per CDI request context as Quarkus Security memoize
     * this deferred identity, therefore further subscriptions to the returned {@link Uni} are cheap.
     *
     * @return {@link SecurityIdentity}; never null
     * @see CurrentIdentityAssociation#getDeferredIdentity()
     */
    public Uni<SecurityIdentity> getDeferredIdentity() {
        if (deferredIdentity != null) {
            return deferredIdentity;
        } else if (identity != null) {
            return Uni.createFrom().item(identity);
        } else {
            return deferredIdentity = getIdentityProviderManager().authenticate(AnonymousAuthenticationRequest.INSTANCE);
        }
    }

    /**
     * Retrieve the {@link SecurityIdentity}. It triggers the authentication request when it is set to null.
     *
     * @return {@link SecurityIdentity}; never null
     * @throws BlockingOperationNotAllowedException when the {@link SecurityIdentity} is set to null and blocking
     *         operations are not allowed
     * @see CurrentIdentityAssociation#getIdentity()
     */
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

    /**
     * Retrieve the {@link SecurityIdentity} without triggering an authentication request.
     * A null identity value means that the authentication has not yet occurred.
     *
     * @return the current {@link SecurityIdentity}, or {@code null} if none exists
     */
    public SecurityIdentity getIdentityValue() {
        return identity;
    }
}
