package io.quarkus.security.spi.runtime;

import jakarta.enterprise.inject.spi.BeanManager;

public record SecurityEventHelper(boolean fireEventOnSuccess, boolean fireEventOnFailure) {

    public static SecurityEventHelper of(SecurityEvent successEvent, SecurityEvent failureEvent, BeanManager beanManager,
            boolean enabled) {
        if (enabled) {
            boolean fireAllSecurityEvents = !beanManager.resolveObserverMethods(SecurityEvent.NOOP).isEmpty();
            if (fireAllSecurityEvents) {
                return new SecurityEventHelper(true, true);
            } else {
                return new SecurityEventHelper(
                        !beanManager.resolveObserverMethods(successEvent).isEmpty(),
                        !beanManager.resolveObserverMethods(failureEvent).isEmpty());
            }
        } else {
            return new SecurityEventHelper(false, false);
        }
    }

    /**
     * @return true if given event type is observed and security events are enabled
     */
    public static boolean eventObserved(SecurityEvent event, BeanManager beanManager, boolean enabled) {
        return of(event, event, beanManager, enabled).fireEventOnFailure();
    }
}
