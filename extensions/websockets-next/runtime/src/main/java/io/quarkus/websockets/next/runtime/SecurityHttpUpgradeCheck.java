package io.quarkus.websockets.next.runtime;

import static io.netty.handler.codec.http.HttpHeaderNames.CACHE_CONTROL;
import static io.netty.handler.codec.http.HttpHeaderNames.LOCATION;

import java.util.List;
import java.util.Map;
import java.util.Objects;

import io.quarkus.security.ForbiddenException;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.spi.runtime.AuthorizationFailureEvent;
import io.quarkus.security.spi.runtime.AuthorizationSuccessEvent;
import io.quarkus.security.spi.runtime.MethodDescription;
import io.quarkus.security.spi.runtime.SecurityCheck;
import io.quarkus.security.spi.runtime.SecurityEventHelper;
import io.quarkus.vertx.http.runtime.security.HttpSecurityPolicy;
import io.quarkus.websockets.next.HttpUpgradeCheck;
import io.smallrye.mutiny.Uni;

public final class SecurityHttpUpgradeCheck implements HttpUpgradeCheck {

    public static final int BEAN_PRIORITY = Integer.MAX_VALUE - 100;
    public static final String SECURED_ENDPOINT_ID_KEY = SecurityHttpUpgradeCheck.class.getName() + ".ENDPOINT_ID";
    public static final String HTTP_REQUEST_KEY = SecurityHttpUpgradeCheck.class.getName() + ".HTTP_REQUEST";

    private final String redirectUrl;
    private final Map<String, SecurityCheck> endpointToCheck;
    private final Map<String, HttpSecurityPolicy> endpointToPolicy;
    private final SecurityEventHelper<AuthorizationSuccessEvent, AuthorizationFailureEvent> securityEventHelper;

    SecurityHttpUpgradeCheck(String redirectUrl, Map<String, SecurityCheck> endpointToCheck,
            SecurityEventHelper<AuthorizationSuccessEvent, AuthorizationFailureEvent> securityEventHelper) {
        this.redirectUrl = redirectUrl;
        this.endpointToCheck = Map.copyOf(endpointToCheck);
        this.securityEventHelper = securityEventHelper;
        this.endpointToPolicy = Map.of(); // FIXME: impl. me!
        // TODO: authorization policy
        //  - must be reapplied on security identity update
        //  - map endpoint -> methodDescription -> and use AuthorizationPolicyStorage to get endpoint policies once
        //  - have a map "endpoint to HttpSecurityPolicies" and figure how security events can be fired
        //  - security identity can be updated, how to do that from here? we update the RoutingContext
        //  - JaxRsPathMatchingHttpSecurityPolicy
        //  - FIXME: authentication event as well?????????? or not!!
    }

    @Override
    public Uni<CheckResult> perform(HttpUpgradeContext context) {
        final SecurityCheck securityCheck = endpointToCheck.get(context.endpointId());
        final HttpSecurityPolicy httpSecurityPolicy = endpointToPolicy.get(context.endpointId());
        return context.securityIdentity()
                .chain(identity -> {
                    Uni<Object> authorizationCheck = Uni.createFrom().nullItem();
                    if (httpSecurityPolicy != null) {
                        if (securityCheck != null) {
                            // FIXME: check not null
                        } else {
                            // FIXME: check null
                        }
                    } else {
                        if (securityCheck != null) {
                            // FIXME: check not null
                        } else {
                            // FIXME: this shouldn't be allowed probably? doesn't make a sense if both authorizations are null
                        }
                    }

                    return securityCheck
                            // security check
                            .nonBlockingApply(identity, (MethodDescription) null, null)
                            // map authorization result to the CheckResult
                            .replaceWith(() -> permitUpgrade(identity, securityCheck, context))
                            .onFailure(SecurityException.class)
                            .recoverWithItem(t -> rejectUpgrade(t, identity, securityCheck, context));
                });
    }

    @Override
    public boolean appliesTo(String endpointId) {
        return endpointToCheck.containsKey(endpointId);
    }

    private CheckResult permitUpgrade(SecurityIdentity identity, SecurityCheck securityCheck, HttpUpgradeContext context) {
        if (securityEventHelper.fireEventOnSuccess()) {
            String authorizationContext = securityCheck.getClass().getName();
            AuthorizationSuccessEvent successEvent = new AuthorizationSuccessEvent(identity, authorizationContext,
                    Map.of(SECURED_ENDPOINT_ID_KEY, context.endpointId(), HTTP_REQUEST_KEY, context.httpRequest()));
            securityEventHelper.fireSuccessEvent(successEvent);
        }
        return CheckResult.permitUpgradeSync();
    }

    private CheckResult rejectUpgrade(Throwable throwable, SecurityIdentity identity, SecurityCheck securityCheck,
            HttpUpgradeContext context) {
        if (securityEventHelper.fireEventOnFailure()) {
            String authorizationContext = securityCheck.getClass().getName();
            AuthorizationFailureEvent failureEvent = new AuthorizationFailureEvent(identity, throwable, authorizationContext,
                    Map.of(SECURED_ENDPOINT_ID_KEY, context.endpointId(), HTTP_REQUEST_KEY, context.httpRequest()));
            securityEventHelper.fireFailureEvent(failureEvent);
        }
        if (redirectUrl != null) {
            return CheckResult.rejectUpgradeSync(302,
                    Map.of(LOCATION.toString(), List.of(redirectUrl),
                            CACHE_CONTROL.toString(), List.of("no-store")));
        } else if (throwable instanceof ForbiddenException) {
            return CheckResult.rejectUpgradeSync(403);
        } else {
            return CheckResult.rejectUpgradeSync(401);
        }
    }

}
