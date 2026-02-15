package io.quarkus.vertx.http.runtime.security;

import java.util.Map;

import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.spi.runtime.AbstractSecurityEvent;

public final class FormAuthenticationEvent extends AbstractSecurityEvent {

    public static final String FORM_CONTEXT = "io.quarkus.vertx.http.runtime.security.FormAuthenticationEvent#CONTEXT";
    public static final String PRINCIPAL_NAME = "io.quarkus.vertx.http.runtime.security.FormAuthenticationEvent#PRINCIPAL_NAME";
    public static final String FAILURE = "io.quarkus.vertx.http.runtime.security.FormAuthenticationEvent#FAILURE";
    public static final String TOKEN = "io.quarkus.vertx.http.runtime.security.FormAuthenticationEvent#TOKEN";

    public enum FormEventType {
        /**
         * Event fired when a user was successfully authenticated with a call to the Form mechanism POST location.
         */
        FORM_LOGIN,
        /**
         * Event fired when authentication token was requested, the request was processed and sent.
         * If Quarkus failed to send the token, this event is fired with the failure stored in the event properties.
         */
        AUTHENTICATION_TOKEN
    }

    private FormAuthenticationEvent(SecurityIdentity securityIdentity, Map<String, Object> eventProperties) {
        super(securityIdentity, eventProperties);
    }

    static FormAuthenticationEvent createLoginEvent(SecurityIdentity identity) {
        return new FormAuthenticationEvent(identity, Map.of(FORM_CONTEXT, FormEventType.FORM_LOGIN.toString()));
    }

    static FormAuthenticationEvent createAuthenticationTokenEvent(SecurityIdentity identity) {
        return new FormAuthenticationEvent(identity, Map.of(FORM_CONTEXT, FormEventType.AUTHENTICATION_TOKEN.toString()));
    }

    static FormAuthenticationEvent createAuthenticationTokenEvent(SecurityIdentity identity, char[] token) {
        return new FormAuthenticationEvent(identity,
                Map.of(FORM_CONTEXT, FormEventType.AUTHENTICATION_TOKEN.toString(), TOKEN, token));
    }

    static FormAuthenticationEvent createAuthenticationTokenEvent(Throwable failure, String principalName) {
        return new FormAuthenticationEvent(null, Map.of(FORM_CONTEXT, FormEventType.AUTHENTICATION_TOKEN.toString(),
                PRINCIPAL_NAME, principalName, FAILURE, failure));
    }
}
