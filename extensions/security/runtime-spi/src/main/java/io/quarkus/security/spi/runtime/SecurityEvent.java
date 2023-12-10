package io.quarkus.security.spi.runtime;

import java.util.Map;

import io.quarkus.security.identity.SecurityIdentity;

/**
 * Common interface for all CDI security events, which allows to consume all the events.
 */
public interface SecurityEvent {

    SecurityEvent NOOP = new SecurityEvent() {
        @Override
        public SecurityIdentity getSecurityIdentity() {
            return null;
        }

        @Override
        public Map<String, Object> getEventProperties() {
            return Map.of();
        }
    };

    /**
     * @return SecurityIdentity or {@code null} when not available
     */
    SecurityIdentity getSecurityIdentity();

    /**
     * @return map of event-specific properties; must never be null
     */
    Map<String, Object> getEventProperties();
}
