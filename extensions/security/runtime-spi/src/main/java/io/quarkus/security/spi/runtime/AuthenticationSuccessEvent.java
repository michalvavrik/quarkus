package io.quarkus.security.spi.runtime;

import java.util.Map;

import io.quarkus.security.identity.SecurityIdentity;

/**
 * Security event fired when request authentication succeeded.
 * This event is never fired for anonymous {@link SecurityIdentity}.
 */
public class AuthenticationSuccessEvent implements SecurityEvent {

    public static final AuthenticationSuccessEvent EMPTY_INSTANCE = new AuthenticationSuccessEvent(null, null);
    private final Map<String, Object> eventProperties;
    private final SecurityIdentity securityIdentity;

    public AuthenticationSuccessEvent(SecurityIdentity securityIdentity, Map<String, Object> eventProperties) {
        this.securityIdentity = securityIdentity;
        if (eventProperties != null && !eventProperties.isEmpty()) {
            this.eventProperties = Map.copyOf(eventProperties);
        } else {
            this.eventProperties = Map.of();
        }
    }

    @Override
    public SecurityIdentity getSecurityIdentity() {
        return securityIdentity;
    }

    @Override
    public Map<String, Object> getEventProperties() {
        return eventProperties;
    }

}
