package io.quarkus.security.spi.runtime;

import io.quarkus.security.identity.SecurityIdentity;
import io.smallrye.mutiny.Uni;

/**
 * TODO: write javadoc
 * TODO: rename according to the Sergeys proposal!
 */
public interface TokenSender {

    /**
     * TODO: write javadoc
     *
     * @param tokenRequest token request
     * @return {@link Uni} with void item or failure; never null
     */
    Uni<Void> sendToken(TokenRequest tokenRequest);

    // TODO: mention that this will be filled with nonsense once `sendToken` finishes
    record TokenRequest(char[] token, SecurityIdentity securityIdentity) {
    }
}
