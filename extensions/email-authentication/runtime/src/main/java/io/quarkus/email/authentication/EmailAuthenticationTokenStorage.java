package io.quarkus.email.authentication;

import java.security.Principal;

import io.smallrye.mutiny.Uni;
import io.vertx.ext.web.RoutingContext;

/**
 * Email authentication token storage. Should be created as a CDI bean implementing this interface.
 */
public interface EmailAuthenticationTokenStorage {

    /**
     * Stores generated email authentication token. This method must complete before the HTTP request to generate
     * the token is completed. If you wish to reject the request, we recommend to return {@link Uni} with the failure.
     * It is desirable for this method to have constant execution time, because we don't want to signal by the response
     * time whether the given principal exists or not. Please note that this method is called for every request to generate
     * token, regardless of whether the principal name exists or not. Depending on your storage, you may want to validate
     * whether the associated principal exists.
     *
     * @param tokenRequest {@link EmailAuthenticationTokenRequest}; the token array will be cleared on {@link Uni} termination
     * @param principalName {@link Principal#getName()}
     * @param routingContext incoming HTTP request event
     * @return {@link Uni} with void if the token was stored successfully, or failure if the request to store this token
     *         was rejected
     */
    Uni<Void> storeToken(EmailAuthenticationTokenRequest tokenRequest, String principalName, RoutingContext routingContext);

    /**
     * Retrieves {@link io.quarkus.security.identity.SecurityIdentity}'s {@link Principal#getName()} based
     * on the given email authentication token.
     *
     * @param token email authentication token
     * @param routingContext incoming HTTP request event
     * @return {@link Uni} with principal name or null item for unknown, rejected or invalid token
     */
    Uni<String> findPrincipalNameByToken(String token, RoutingContext routingContext);

    /**
     * Email authentication token request.
     */
    interface EmailAuthenticationTokenRequest {

        /**
         * Retrieves email authentication token (generated the first time this method is invoked).
         *
         * @return generated email authentication token
         */
        char[] token();

    }

    /**
     * Default {@link EmailAuthenticationTokenStorage} implementation. This CDI bean is useful when you are implementing
     * mitigation for security risks such as a replay attack, brute-force protection, or events for failed logins.
     * Example usage:
     *
     * <pre>
     * {@code
     * import io.quarkus.security.AuthenticationFailedException;
     * import io.smallrye.mutiny.Uni;
     * import io.vertx.ext.web.RoutingContext;
     * import jakarta.enterprise.context.ApplicationScoped;
     *
     * &#64;ApplicationScoped
     * class CustomEmailAuthenticationTokenStorage implements EmailAuthenticationTokenStorage {
     *
     *     private final EmailAuthenticationTokenStorage delegate;
     *
     *     CustomEmailAuthenticationTokenStorage(DefaultEmailAuthenticationTokenStorage defaultStorage) {
     *         this.delegate = defaultStorage;
     *     }
     *
     *     &#64;Override
     *     public Uni<Void> storeToken(char[] token, String principalName, RoutingContext routingContext) {
     *         if (exceededNumberOfRequests(principalName) || isBlacklistedIpAddress(routingContext)) {
     *             return Uni.createFrom().failure(new AuthenticationFailedException());
     *         }
     *         return delegate.storeToken(token, principalName, routingContext);
     *     }
     *
     *     @Override
     *     public Uni<String> findPrincipalNameByToken(String token, RoutingContext routingContext) {
     *         if (tokenAlreadyUsedToAuthenticate(token)) {
     *             return Uni.createFrom().failure(new AuthenticationFailedException());
     *         }
     *         return delegate.findPrincipalNameByToken(token, routingContext);
     *     }
     *
     *     // your implementation comes here
     * }
     * }
     * </pre>
     */
    interface DefaultEmailAuthenticationTokenStorage extends EmailAuthenticationTokenStorage {

    }

}
