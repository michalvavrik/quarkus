package io.quarkus.security.spi.runtime;

import java.util.HashMap;
import java.util.Map;

import io.quarkus.security.identity.SecurityIdentity;

/**
 * Security event that should be fired when the {@link SecurityIdentity} passed security constrain,
 * such as {@link SecurityCheck} or HTTP Security policy.
 */
public final class AuthorizationSuccessEvent implements SecurityEvent {
    public static final AuthorizationSuccessEvent EMPTY_INSTANCE = new AuthorizationSuccessEvent(null, null);
    public static final String AUTHORIZATION_CONTEXT = AuthorizationSuccessEvent.class.getName() + ".CONTEXT";
    private final SecurityIdentity securityIdentity;
    private final Map<String, Object> eventProperties;

    public AuthorizationSuccessEvent(SecurityIdentity securityIdentity, Map<String, Object> eventProperties) {
        this(securityIdentity, null, eventProperties);
    }

    public AuthorizationSuccessEvent(SecurityIdentity securityIdentity, String authorizationContext,
            Map<String, Object> eventProperties) {
        this.securityIdentity = securityIdentity;
        this.eventProperties = new HashMap<>();
        if (eventProperties != null && !eventProperties.isEmpty()) {
            this.eventProperties.putAll(eventProperties);
        }
        if (authorizationContext != null) {
            this.eventProperties.put(AUTHORIZATION_CONTEXT, authorizationContext);
        }
    }

    @Override
    public SecurityIdentity getSecurityIdentity() {
        return securityIdentity;
    }

    @Override
    public Map<String, Object> getEventProperties() {
        return Map.copyOf(eventProperties);
    }
}
