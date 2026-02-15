package io.quarkus.vertx.http.security.form.token;

import java.security.Principal;

import io.smallrye.mutiny.Uni;

/**
 * Form authentication token storage. Should be created as a CDI bean implementing this interface.
 */
public interface FormAuthenticationTokenStorage {

    /**
     * Stores generated form authentication token.
     *
     * @param token form authentication token
     * @param principalName {@link Principal#getName()}
     * @return {@link Uni} with void item or failure, if the attempt to store the token failed
     */
    Uni<Void> storeToken(char[] token, String principalName);

    /**
     * Retrieves form authentication token based on given token.
     *
     * @param token form authentication token
     * @return {@link Uni} with fond token or null item for unknown or invalid token
     */
    Uni<String> findPrincipalNameByToken(char[] token);

}
