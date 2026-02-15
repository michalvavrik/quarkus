package io.quarkus.vertx.http.security.form.token;

import java.security.Principal;

import io.smallrye.mutiny.Uni;
import io.vertx.ext.web.RoutingContext;

/**
 * Form authentication token storage. Should be created as a CDI bean implementing this interface.
 */
public interface FormAuthenticationTokenStorage {

    /**
     * Stores generated form authentication token. This method must complete before the HTTP request to generate the token
     * is completed. Blocking and asynchronous tasks should be scheduled using Vert.x. It is desirable for this method
     * to run shortly, because we don't want to signal by the response time whether the given principal exists or not.
     * Please note that this method is called for every request to generate token, regardless of whether the principal
     * name exists or not. Depending on your storage, you may want to validate whether the associated principal exists.
     *
     * @param token form authentication token
     * @param principalName {@link Principal#getName()}
     * @param routingContext incoming HTTP request event
     */
    void storeToken(char[] token, String principalName, RoutingContext routingContext);

    /**
     * Retrieves form authentication token based on given token.
     *
     * @param token form authentication token
     * @param routingContext incoming HTTP request event
     * @return {@link Uni} with fond token or null item for unknown or invalid token
     */
    Uni<String> findPrincipalNameByToken(String token, RoutingContext routingContext);

}
