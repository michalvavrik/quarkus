package io.quarkus.vertx.http.security.form.token;

import java.security.Principal;

import io.quarkus.vertx.http.runtime.security.HttpSecurityConfiguration;
import io.smallrye.mutiny.Uni;
import io.vertx.ext.web.RoutingContext;

/**
 * Form authentication token storage. Should be created as a CDI bean implementing this interface.
 */
public interface FormAuthenticationTokenStorage {

    /**
     * Stores generated form authentication token. This method must complete before the HTTP request to generate the token
     * is completed. If you wish to reject the request, we recommend to return {@link Uni} with the failure.
     * It is desirable for this method to run shortly, because we don't want to signal by the response time
     * whether the given principal exists or not. Please note that this method is called for every request to generate
     * token, regardless of whether the principal name exists or not. Depending on your storage, you may want to validate
     * whether the associated principal exists.
     *
     * @param token form authentication token
     * @param principalName {@link Principal#getName()}
     * @param routingContext incoming HTTP request event
     * @return {@link Uni} with void if the token was stored successfully, or failure if the request to store this token
     *         was rejected
     */
    Uni<Void> storeToken(char[] token, String principalName, RoutingContext routingContext);

    /**
     * Retrieves form authentication token based on given token.
     *
     * @param token form authentication token
     * @param routingContext incoming HTTP request event
     * @return {@link Uni} with fond token or null item for unknown or invalid token
     */
    Uni<String> findPrincipalNameByToken(String token, RoutingContext routingContext);

    /**
     * Creates default {@link FormAuthenticationTokenStorage}. This method is useful, when you are implementing
     * mitigation for security risks such as a replay attack, brute-force protection, or events for failed logins.
     * Please note that this method can only be used after the Quarkus application has started and Quarkus Security
     * is fully initialized. Typically, you would use it from the {@link jakarta.enterprise.context.ApplicationScoped}
     * bean constructor together in the delegation pattern. Example usage:
     *
     * <pre>
     * {@code
     * import io.quarkus.security.AuthenticationFailedException;
     * import io.smallrye.mutiny.Uni;
     * import io.vertx.ext.web.RoutingContext;
     * import jakarta.enterprise.context.ApplicationScoped;
     *
     * &#64;ApplicationScoped
     * class CustomFormAuthenticationTokenStorage implements FormAuthenticationTokenStorage {
     *
     *     private final FormAuthenticationTokenStorage delegate;
     *
     *     CustomFormAuthenticationTokenStorage() {
     *         this.delegate = FormAuthenticationTokenStorage.createDefaultStorage();
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
    static FormAuthenticationTokenStorage createDefaultStorage() {
        return HttpSecurityConfiguration.createDefaultFormAuthenticationTokenStorage();
    }
}
