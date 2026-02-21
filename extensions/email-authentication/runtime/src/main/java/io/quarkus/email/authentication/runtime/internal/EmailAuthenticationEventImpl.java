package io.quarkus.email.authentication.runtime.internal;

import static io.quarkus.email.authentication.EmailAuthenticationEvent.EmailAuthenticationEventType.AUTHENTICATION_TOKEN;
import static io.quarkus.email.authentication.EmailAuthenticationEvent.EmailAuthenticationEventType.EMAIL_LOGIN;
import static io.quarkus.vertx.http.runtime.security.HttpSecurityUtils.ROUTING_CONTEXT_ATTRIBUTE;

import java.util.Map;

import io.quarkus.email.authentication.EmailAuthenticationEvent;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.spi.runtime.AbstractSecurityEvent;
import io.vertx.ext.web.RoutingContext;

final class EmailAuthenticationEventImpl extends AbstractSecurityEvent implements EmailAuthenticationEvent {

    private final EmailAuthenticationEventType eventType;

    EmailAuthenticationEventImpl(EmailAuthenticationEventType eventType, SecurityIdentity securityIdentity,
            Map<String, Object> eventProperties) {
        super(securityIdentity, eventProperties);
        this.eventType = eventType;
    }

    @Override
    public EmailAuthenticationEventType getEventType() {
        return eventType;
    }

    static EmailAuthenticationEvent createEmptyEvent() {
        return new EmailAuthenticationEventImpl(EMAIL_LOGIN, null, null);
    }

    static EmailAuthenticationEvent createLoginEvent(SecurityIdentity identity, String token, RoutingContext routingContext) {
        return new EmailAuthenticationEventImpl(EMAIL_LOGIN, identity,
                Map.of(AUTHENTICATION_TOKEN_KEY, token, ROUTING_CONTEXT_ATTRIBUTE, routingContext));
    }

    static EmailAuthenticationEvent createAuthenticationTokenEvent(SecurityIdentity identity, String principalName,
            char[] token, RoutingContext routingContext) {
        return new EmailAuthenticationEventImpl(AUTHENTICATION_TOKEN, identity, Map.of(AUTHENTICATION_TOKEN_KEY, token,
                PRINCIPAL_NAME_KEY, principalName, ROUTING_CONTEXT_ATTRIBUTE, routingContext));
    }

    static EmailAuthenticationEvent createAuthenticationTokenEvent(Throwable failure, String principalName,
            RoutingContext routingContext) {
        return new EmailAuthenticationEventImpl(AUTHENTICATION_TOKEN, null,
                Map.of(PRINCIPAL_NAME_KEY, principalName, FAILURE_KEY, failure, ROUTING_CONTEXT_ATTRIBUTE, routingContext));
    }
}
