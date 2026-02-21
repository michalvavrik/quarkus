package io.quarkus.email.authentication.runtime.internal;

import io.quarkus.runtime.RuntimeValue;
import io.quarkus.runtime.annotations.Recorder;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.vertx.http.runtime.security.QuarkusHttpUser;
import io.quarkus.vertx.http.runtime.security.SecurityHandlerPriorities;
import io.smallrye.mutiny.Uni;
import io.smallrye.mutiny.subscription.UniSubscriber;
import io.smallrye.mutiny.subscription.UniSubscription;
import io.vertx.core.Handler;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;

@Recorder
public class EmailAuthenticationRecorder {

    private final RuntimeValue<EmailAuthenticationConfig> configRuntimeValue;

    EmailAuthenticationRecorder(RuntimeValue<EmailAuthenticationConfig> configRuntimeValue) {
        this.configRuntimeValue = configRuntimeValue;
    }

    /**
     * Makes sure that email authentication works with disabled eager authentication.
     * This is similar to what we do for the form-based authentication, thus refer there for more context.
     */
    public void registerEmailAuthRouteHandler(RuntimeValue<Router> httpRouter) {
        var config = configRuntimeValue.getValue();
        var handler = createEmailAuthRouteHandler();
        httpRouter.getValue()
                .post(config.tokenGenerationLocation())
                .order(-1 * SecurityHandlerPriorities.FORM_AUTHENTICATION)
                .handler(handler);
        httpRouter.getValue()
                .post(config.postLocation())
                .order(-1 * SecurityHandlerPriorities.FORM_AUTHENTICATION)
                .handler(handler);
    }

    private static Handler<RoutingContext> createEmailAuthRouteHandler() {
        return new Handler<RoutingContext>() {

            @Override
            public void handle(RoutingContext event) {
                Uni<SecurityIdentity> user = event.get(QuarkusHttpUser.DEFERRED_IDENTITY_KEY);
                user.subscribe().withSubscriber(new UniSubscriber<SecurityIdentity>() {
                    @Override
                    public void onSubscribe(UniSubscription uniSubscription) {

                    }

                    @Override
                    public void onItem(SecurityIdentity securityIdentity) {
                        if (!event.response().ended()) {
                            event.response().end();
                        }
                    }

                    @Override
                    public void onFailure(Throwable throwable) {
                        if (!event.response().ended() && !event.failed()) {
                            event.fail(throwable);
                        }
                    }
                });
            }
        };
    }

}
