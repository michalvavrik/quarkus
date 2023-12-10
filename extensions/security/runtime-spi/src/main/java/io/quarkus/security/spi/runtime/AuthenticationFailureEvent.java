package io.quarkus.security.spi.runtime;

import java.util.HashMap;
import java.util.Map;

import io.quarkus.security.identity.SecurityIdentity;

/**
 * Security event fired when authentication failed.
 */
public class AuthenticationFailureEvent implements SecurityEvent {

    public static final AuthenticationFailureEvent EMPTY_INSTANCE = new AuthenticationFailureEvent(null, null);
    public static final String AUTHENTICATION_FAILURE_KEY = AuthenticationFailureEvent.class.getName() + ".FAILURE";
    private final Map<String, Object> eventProperties;

    public AuthenticationFailureEvent(Throwable authenticationFailure, Map<String, Object> eventProperties) {
        this.eventProperties = new HashMap<>();
        if (authenticationFailure != null) {
            this.eventProperties.put(AUTHENTICATION_FAILURE_KEY, authenticationFailure);
        }
        if (eventProperties != null && !eventProperties.isEmpty()) {
            this.eventProperties.putAll(eventProperties);
        }
    }

    @Override
    public SecurityIdentity getSecurityIdentity() {
        return null;
    }

    @Override
    public Map<String, Object> getEventProperties() {
        return Map.copyOf(eventProperties);
    }

    public Throwable getAuthenticationFailure() {
        return (Throwable) eventProperties.get(AUTHENTICATION_FAILURE_KEY);
    }
}
