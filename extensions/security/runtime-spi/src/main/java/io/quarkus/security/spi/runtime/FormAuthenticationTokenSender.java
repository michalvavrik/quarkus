package io.quarkus.security.spi.runtime;

import io.quarkus.security.identity.SecurityIdentity;
import io.smallrye.mutiny.Uni;

/**
 * Form authentication token sender. Should be created as a CDI bean implementing this interface.
 */
public interface FormAuthenticationTokenSender {

    /**
     * Sends form authentication token to the {@link SecurityIdentity}.
     *
     * @param token form authentication token; the array is emptied on {@link Uni} termination
     * @param securityIdentity {@link SecurityIdentity} to which the token should be sent
     * @return {@link Uni} with void item or failure; never null
     */
    Uni<Void> sendToken(char[] token, SecurityIdentity securityIdentity);
}
