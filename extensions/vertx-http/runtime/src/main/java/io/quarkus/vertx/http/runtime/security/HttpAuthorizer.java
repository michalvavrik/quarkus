package io.quarkus.vertx.http.runtime.security;

import java.util.ArrayList;
import java.util.List;

import jakarta.enterprise.event.Event;
import jakarta.enterprise.inject.Instance;
import jakarta.enterprise.inject.spi.BeanManager;
import jakarta.inject.Singleton;

import org.eclipse.microprofile.config.inject.ConfigProperty;

import io.quarkus.security.identity.IdentityProviderManager;
import io.quarkus.security.spi.runtime.AuthorizationController;
import io.quarkus.security.spi.runtime.AuthorizationFailureEvent;
import io.quarkus.security.spi.runtime.AuthorizationSuccessEvent;
import io.quarkus.security.spi.runtime.BlockingSecurityExecutor;

/**
 * Class that is responsible for running the HTTP based permission checks
 */
@Singleton
public class HttpAuthorizer extends AbstractHttpAuthorizer {

    HttpAuthorizer(HttpAuthenticator httpAuthenticator, IdentityProviderManager identityProviderManager,
            AuthorizationController controller, Instance<HttpSecurityPolicy> installedPolicies,
            BlockingSecurityExecutor blockingExecutor, BeanManager beanManager,
            Event<AuthorizationFailureEvent> authZFailureEvent, Event<AuthorizationSuccessEvent> authZSuccessEvent,
            @ConfigProperty(name = "quarkus.security.events.enabled") boolean securityEventsEnabled) {
        super(httpAuthenticator, identityProviderManager, controller, toList(installedPolicies), beanManager, blockingExecutor,
                authZFailureEvent, authZSuccessEvent, securityEventsEnabled);
    }

    private static List<HttpSecurityPolicy> toList(Instance<HttpSecurityPolicy> installedPolicies) {
        List<HttpSecurityPolicy> globalPolicies = new ArrayList<>();
        for (HttpSecurityPolicy i : installedPolicies) {
            if (i.name() == null && isNotPathMatchingPolicyWithoutPerms(i)) {
                globalPolicies.add(i);
            }
        }
        return globalPolicies;
    }

    private static boolean isNotPathMatchingPolicyWithoutPerms(HttpSecurityPolicy p) {
        if (p instanceof AbstractPathMatchingHttpSecurityPolicy p1) {
            // path matching policy applies permission policies, if there are no permissions, there is nothing to apply
            return !p1.hasNoPermissions();
        }
        return true;
    }
}
