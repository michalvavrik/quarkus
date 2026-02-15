package io.quarkus.vertx.http.security.form.token;

import jakarta.enterprise.context.ApplicationScoped;

import io.quarkus.security.AuthenticationFailedException;
import io.smallrye.mutiny.Uni;
import io.vertx.ext.web.RoutingContext;

@ApplicationScoped
public class CustomFormAuthenticationTokenStorage implements FormAuthenticationTokenStorage {

    private final FormAuthenticationTokenStorage delegate;

    CustomFormAuthenticationTokenStorage() {
        this.delegate = FormAuthenticationTokenStorage.createDefaultStorage();
    }

    @Override
    public Uni<Void> storeToken(char[] token, String principalName, RoutingContext routingContext) {
        if (exceededNumberOfRequests(principalName) || isBlacklistedIpAddress(routingContext)) {
            return Uni.createFrom().failure(new AuthenticationFailedException());
        }
        return delegate.storeToken(token, principalName, routingContext);
    }

    @Override
    public Uni<String> findPrincipalNameByToken(String token, RoutingContext routingContext) {
        if (tokenAlreadyUsedToAuthenticate(token)) {
            return Uni.createFrom().failure(new AuthenticationFailedException());
        }
        return delegate.findPrincipalNameByToken(token, routingContext);
    }

    private boolean tokenAlreadyUsedToAuthenticate(String token) {
        return false;
    }

    private boolean isBlacklistedIpAddress(RoutingContext routingContext) {
        return false;
    }

    private boolean exceededNumberOfRequests(String principalName) {
        return false;
    }
}
