package io.quarkus.vertx.http.security.token;

import io.quarkus.security.credential.PasswordCredential;
import io.quarkus.security.identity.SecurityIdentity;
import io.smallrye.mutiny.Uni;

/**
 * An interface responsible for delivering of the authentication token to the user.
 * This interface should be implemented as {@link jakarta.enterprise.context.ApplicationScoped}
 * or {@link jakarta.inject.Singleton} CDI bean.
 */
public interface FormAuthenticationTokenSender {

    /**
     * Sends the authentication token to the user.
     *
     * @param securityIdentity represents user for which the authentication token has been requested
     * @param authenticationTokenCredential the authentication token credential
     * @return {@link Uni}; must not be null
     */
    Uni<Void> send(SecurityIdentity securityIdentity, PasswordCredential authenticationTokenCredential);

}
