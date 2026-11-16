package io.quarkus.vertx.http.runtime.security;

import java.util.function.Consumer;

import io.vertx.ext.web.RoutingContext;

/**
 * Interceptor that selects authentication mechanism based
 * on the {@link io.quarkus.vertx.http.runtime.security.annotation.HttpAuthenticationMechanism} annotation.
 *
 * @param authMechanismName name of the selected authentication mechanism
 */
public record AuthMechanismSelectionInterceptor(String authMechanismName) implements Consumer<RoutingContext> {

    @Override
    public void accept(RoutingContext routingContext) {
        // when endpoint is annotated with @HttpAuthenticationMechanism("my-mechanism"), we add this mechanism
        // to the event so that when request is being authenticated, the HTTP authenticator will know
        // what mechanism should be used
        HttpAuthenticator.selectAuthMechanism(routingContext, authMechanismName);
    }

}
