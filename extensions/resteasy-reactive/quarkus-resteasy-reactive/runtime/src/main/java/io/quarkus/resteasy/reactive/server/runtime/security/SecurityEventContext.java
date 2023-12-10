package io.quarkus.resteasy.reactive.server.runtime.security;

import jakarta.enterprise.event.Event;
import jakarta.enterprise.inject.spi.BeanManager;
import jakarta.inject.Singleton;

import org.eclipse.microprofile.config.inject.ConfigProperty;

import io.quarkus.security.spi.runtime.AuthorizationFailureEvent;
import io.quarkus.security.spi.runtime.AuthorizationSuccessEvent;
import io.quarkus.security.spi.runtime.SecurityEventHelper;

@Singleton
public class SecurityEventContext {

    final boolean fireAuthorizationFailureEvent;
    final boolean fireAuthorizationSuccessEvent;
    final Event<AuthorizationFailureEvent> authorizationFailureEvent;
    final Event<AuthorizationSuccessEvent> authorizationSuccessEvent;

    SecurityEventContext(Event<AuthorizationFailureEvent> authorizationFailureEvent,
            @ConfigProperty(name = "quarkus.security.events.enabled") boolean securityEventsEnabled,
            Event<AuthorizationSuccessEvent> authorizationSuccessEvent, BeanManager beanManager) {
        var eventHelper = SecurityEventHelper.of(AuthorizationSuccessEvent.EMPTY_INSTANCE,
                AuthorizationFailureEvent.EMPTY_INSTANCE, beanManager, securityEventsEnabled);
        this.fireAuthorizationSuccessEvent = eventHelper.fireEventOnSuccess();
        this.fireAuthorizationFailureEvent = eventHelper.fireEventOnFailure();
        this.authorizationSuccessEvent = eventHelper.fireEventOnSuccess() ? authorizationSuccessEvent : null;
        this.authorizationFailureEvent = eventHelper.fireEventOnFailure() ? authorizationFailureEvent : null;
    }
}
