package io.quarkus.security.spi.runtime;

import java.util.HashMap;
import java.util.Map;

import io.quarkus.security.identity.SecurityIdentity;

/**
 * Security event that should be fired when the {@link SecurityIdentity} failed security constrain,
 * such as {@link SecurityCheck} or HTTP Security policy.
 */
public final class AuthorizationFailureEvent implements SecurityEvent {
    public static final AuthorizationFailureEvent EMPTY_INSTANCE = new AuthorizationFailureEvent(null, null, null);
    public static final String AUTHORIZATION_FAILURE_KEY = AuthorizationFailureEvent.class.getName()
            + ".FAILURE";
    public static final String AUTHORIZATION_CONTEXT_KEY = AuthorizationFailureEvent.class.getName() + ".CONTEXT";
    private final SecurityIdentity securityIdentity;
    private final Map<String, Object> eventProperties;

    public AuthorizationFailureEvent(SecurityIdentity securityIdentity, Throwable authorizationFailure,
            String authorizationContext) {
        this.securityIdentity = securityIdentity;
        this.eventProperties = toEventProperties(authorizationFailure, authorizationContext);
    }

    public AuthorizationFailureEvent(SecurityIdentity securityIdentity, Throwable authorizationFailure,
            String authorizationContext, Map<String, Object> eventProperties) {
        this(securityIdentity, authorizationFailure, authorizationContext);
        if (eventProperties != null && !eventProperties.isEmpty()) {
            this.eventProperties.putAll(eventProperties);
        }
    }

    public Throwable getAuthorizationFailure() {
        return (Throwable) eventProperties.get(AUTHORIZATION_FAILURE_KEY);
    }

    public String getAuthorizationContext() {
        return (String) eventProperties.get(AUTHORIZATION_CONTEXT_KEY);
    }

    @Override
    public SecurityIdentity getSecurityIdentity() {
        return securityIdentity;
    }

    @Override
    public Map<String, Object> getEventProperties() {
        return Map.copyOf(eventProperties);
    }

    private static Map<String, Object> toEventProperties(Throwable authorizationFailure, String authorizationContext) {
        Map<String, Object> eventProperties = new HashMap<>();
        if (authorizationFailure != null) {
            eventProperties.put(AUTHORIZATION_FAILURE_KEY, authorizationFailure);
        }
        if (authorizationContext != null) {
            eventProperties.put(AUTHORIZATION_CONTEXT_KEY, authorizationContext);
        }
        return eventProperties;
    }
}
